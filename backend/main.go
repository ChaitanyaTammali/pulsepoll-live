package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct { ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`; Name string `bson:"name" json:"name"`; Email string `bson:"email" json:"email"`; Password string `bson:"password" json:"-"`; CreatedAt time.Time `bson:"createdAt" json:"createdAt"` }
type Option struct { ID string `bson:"id" json:"id"`; Label string `bson:"label" json:"label"` }
type Poll struct { ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`; Slug string `bson:"slug" json:"slug"`; OwnerID primitive.ObjectID `bson:"ownerId" json:"ownerId"`; Title string `bson:"title" json:"title"`; Description string `bson:"description,omitempty" json:"description,omitempty"`; Options []Option `bson:"options" json:"options"`; Closed bool `bson:"closed" json:"closed"`; CreatedAt time.Time `bson:"createdAt" json:"createdAt"` }
type Vote struct { ID primitive.ObjectID `bson:"_id,omitempty"`; PollID primitive.ObjectID `bson:"pollId"`; OptionID string `bson:"optionId"`; VoterHash string `bson:"voterHash"`; CreatedAt time.Time `bson:"createdAt"` }
type Server struct { db *mongo.Database; rdb *redis.Client; hub *Hub; jwtSecret []byte }
type Claims struct { UserID string `json:"uid"`; Name string `json:"name"`; jwt.RegisteredClaims }
type Hub struct { rdb *redis.Client }

var slugPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)
var optionPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)
var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func main() {
	ctx := context.Background()
	mongoURI := env("MONGO_URI", "mongodb://localhost:27017")
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI)); if err != nil { log.Fatal(err) }
	if err = client.Ping(ctx, nil); err != nil { log.Fatal("MongoDB connection: ", err) }
	var rdb *redis.Client
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		redisOptions, parseErr := redis.ParseURL(redisURL)
		if parseErr != nil { log.Fatal("REDIS_URL is invalid: ", parseErr) }
		rdb = redis.NewClient(redisOptions)
	} else {
		rdb = redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "localhost:6379"), Password: os.Getenv("REDIS_PASSWORD")})
	}
	if err = rdb.Ping(ctx).Err(); err != nil { log.Fatal("Redis connection: ", err) }
	db := client.Database(env("MONGO_DATABASE", "pulsepoll"))
	_, err = db.Collection("users").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key:"email",Value:1}}, Options: options.Index().SetUnique(true)})
	if err != nil { log.Fatal(err) }
	_, err = db.Collection("polls").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key:"slug",Value:1}}, Options: options.Index().SetUnique(true)})
	if err != nil { log.Fatal(err) }
	_, err = db.Collection("votes").Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key:"pollId",Value:1},{Key:"voterHash",Value:1}}, Options: options.Index().SetUnique(true)})
	if err != nil { log.Fatal(err) }
	secret := os.Getenv("JWT_SECRET"); if len(secret)<32 { log.Fatal("JWT_SECRET must be at least 32 characters") }
	s := &Server{db:db,rdb:rdb,hub:&Hub{rdb:rdb},jwtSecret:[]byte(secret)}
	r := gin.New(); r.Use(gin.Logger(),gin.Recovery(),cors())
	r.GET("/health", func(c *gin.Context){c.JSON(200,gin.H{"status":"ok"})})
	r.POST("/api/auth/signup",s.signup); r.POST("/api/auth/login",s.login)
	api:=r.Group("/api"); api.Use(s.authRequired()); api.POST("/polls",s.createPoll); api.GET("/polls/mine",s.myPolls); api.PATCH("/polls/:slug/close",s.togglePoll)
	r.GET("/api/polls/:slug",s.getPoll); r.POST("/api/polls/:slug/votes",s.castVote); r.GET("/ws/:slug",s.websocket)
	addr:=env("LISTEN_ADDR",":"+env("PORT","8080")); log.Printf("Pulse API listening on %s",addr); log.Fatal(r.Run(addr))
}

func env(key, fallback string) string { if value:=os.Getenv(key); value!="" { return value }; return fallback }
func cors() gin.HandlerFunc { return func(c *gin.Context){ origin:=os.Getenv("FRONTEND_ORIGIN"); if origin=="" { origin="*" }; c.Header("Access-Control-Allow-Origin",origin); c.Header("Access-Control-Allow-Headers","Content-Type, Authorization"); c.Header("Access-Control-Allow-Methods","GET, POST, PATCH, OPTIONS"); if c.Request.Method==http.MethodOptions { c.AbortWithStatus(204);return }; c.Next() } }
func fail(c *gin.Context,status int,msg string){c.JSON(status,gin.H{"error":msg})}
func decode(c *gin.Context,dst any) bool { c.Request.Body=http.MaxBytesReader(c.Writer,c.Request.Body,64*1024); dec:=json.NewDecoder(c.Request.Body); dec.DisallowUnknownFields(); if err:=dec.Decode(dst);err!=nil {fail(c,400,"Please check the information and try again.");return false};if err:=dec.Decode(&struct{}{});err!=io.EOF {fail(c,400,"Please send one valid request.");return false};return true }
func (s *Server) authRequired() gin.HandlerFunc { return func(c *gin.Context){ h:=strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"),"Bearer ")); if h=="" {fail(c,401,"Please sign in to manage polls.");c.Abort();return};claims:=&Claims{};token,err:=jwt.ParseWithClaims(h,claims,func(t *jwt.Token)(any,error){if t.Method.Alg()!=jwt.SigningMethodHS256.Alg(){return nil,fmt.Errorf("unexpected signing method")};return s.jwtSecret,nil});if err!=nil||!token.Valid {fail(c,401,"Please sign in again.");c.Abort();return};id,err:=primitive.ObjectIDFromHex(claims.UserID);if err!=nil {fail(c,401,"Please sign in again.");c.Abort();return};c.Set("userID",id);c.Set("userName",claims.Name);c.Next()} }
func (s *Server) issueToken(u User)(string,error){ claims:=Claims{UserID:u.ID.Hex(),Name:u.Name,RegisteredClaims:jwt.RegisteredClaims{ExpiresAt:jwt.NewNumericDate(time.Now().Add(7*24*time.Hour)),IssuedAt:jwt.NewNumericDate(time.Now())}};return jwt.NewWithClaims(jwt.SigningMethodHS256,claims).SignedString(s.jwtSecret) }
type authInput struct {Name string `json:"name"`;Email string `json:"email"`;Password string `json:"password"`}
func validateAuth(in authInput,signup bool) (string,string,string,bool){name:=strings.TrimSpace(in.Name);email:=strings.ToLower(strings.TrimSpace(in.Email));if signup&&(len([]rune(name))<1||len([]rune(name))>80){return "","","Name must be between 1 and 80 characters.",false};if len(email)>254||!emailPattern.MatchString(email){return "","","Enter a valid email address.",false};if len(in.Password)<8||len(in.Password)>72{return "","","Password must be between 8 and 72 characters.",false};if _,err:=mail.ParseAddress(email);err!=nil{return "","","Enter a valid email address.",false};return name,email,"",true}
func (s *Server) signup(c *gin.Context){var in authInput;if !decode(c,&in){return};name,email,msg,ok:=validateAuth(in,true);if !ok{fail(c,400,msg);return};hash,err:=bcrypt.GenerateFromPassword([]byte(in.Password),bcrypt.DefaultCost);if err!=nil{fail(c,500,"Could not create account.");return};u:=User{Name:name,Email:email,Password:string(hash),CreatedAt:time.Now().UTC()};_,err=s.db.Collection("users").InsertOne(c, &u);if mongo.IsDuplicateKeyError(err){fail(c,409,"An account with that email already exists.");return};if err!=nil{fail(c,500,"Could not create account.");return};token,err:=s.issueToken(u);if err!=nil{fail(c,500,"Could not create session.");return};c.JSON(201,gin.H{"token":token,"user":gin.H{"id":u.ID.Hex(),"name":u.Name,"email":u.Email}})}
func (s *Server) login(c *gin.Context){var in authInput;if !decode(c,&in){return};_,email,msg,ok:=validateAuth(in,false);if !ok{fail(c,400,msg);return};var u User;if err:=s.db.Collection("users").FindOne(c,bson.M{"email":email}).Decode(&u);err!=nil||bcrypt.CompareHashAndPassword([]byte(u.Password),[]byte(in.Password))!=nil{fail(c,401,"Email or password is incorrect.");return};token,err:=s.issueToken(u);if err!=nil{fail(c,500,"Could not create session.");return};c.JSON(200,gin.H{"token":token,"user":gin.H{"id":u.ID.Hex(),"name":u.Name,"email":u.Email}})}
type optionInput struct {Label string `json:"label"`}
type createInput struct {Title string `json:"title"`;Description string `json:"description"`;Options []optionInput `json:"options"`}
func validatePoll(in createInput)(string,string,[]Option,string,bool){title:=strings.TrimSpace(in.Title);desc:=strings.TrimSpace(in.Description);if len([]rune(title))<3||len([]rune(title))>180{return "","",nil,"Question must be between 3 and 180 characters.",false};if len([]rune(desc))>500{return "","",nil,"Context must be 500 characters or fewer.",false};if len(in.Options)<2||len(in.Options)>8{return "","",nil,"Add between 2 and 8 answer options.",false};opts:=make([]Option,0,len(in.Options));seen:=map[string]bool{};for _,o:=range in.Options{label:=strings.TrimSpace(o.Label);if len([]rune(label))<1||len([]rune(label))>100{return "","",nil,"Each answer must be between 1 and 100 characters.",false};key:=strings.ToLower(label);if seen[key]{return "","",nil,"Answer options must be unique.",false};seen[key]=true;id:=primitive.NewObjectID().Hex();opts=append(opts,Option{ID:id,Label:label})};return title,desc,opts,"",true}
func (s *Server) createPoll(c *gin.Context){var in createInput;if !decode(c,&in){return};title,desc,opts,msg,ok:=validatePoll(in);if !ok{fail(c,400,msg);return};owner:=c.MustGet("userID").(primitive.ObjectID);p:=Poll{ID:primitive.NewObjectID(),Slug:primitive.NewObjectID().Hex(),OwnerID:owner,Title:title,Description:desc,Options:opts,CreatedAt:time.Now().UTC()};if _,err:=s.db.Collection("polls").InsertOne(c,&p);err!=nil{fail(c,500,"Could not create poll.");return};counts:=map[string]int64{};for _,o:=range opts{counts[o.ID]=0};s.writeCounts(c,p.Slug,counts);c.JSON(201,p)}
func (s *Server) myPolls(c *gin.Context){owner:=c.MustGet("userID").(primitive.ObjectID);cur,err:=s.db.Collection("polls").Find(c,bson.M{"ownerId":owner},options.Find().SetSort(bson.D{{Key:"createdAt",Value:-1}}).SetLimit(100));if err!=nil{fail(c,500,"Could not load polls.");return};var polls []Poll;if cur.All(c,&polls)!=nil{fail(c,500,"Could not load polls.");return};if polls==nil{polls=[]Poll{}};c.JSON(200,gin.H{"polls":polls})}
func (s *Server) togglePoll(c *gin.Context){slug:=c.Param("slug");if !slugPattern.MatchString(slug){fail(c,400,"This poll link is not valid.");return};owner:=c.MustGet("userID").(primitive.ObjectID);var p Poll;if err:=s.db.Collection("polls").FindOne(c,bson.M{"slug":slug,"ownerId":owner}).Decode(&p);err!=nil{fail(c,404,"Poll not found.");return};p.Closed=!p.Closed;if _,err:=s.db.Collection("polls").UpdateOne(c,bson.M{"_id":p.ID},bson.M{"$set":bson.M{"closed":p.Closed}});err!=nil{fail(c,500,"Could not update poll.");return};s.publish(c,slug,gin.H{"type":"poll","poll":p});c.JSON(200,gin.H{"poll":p})}
func (s *Server) getPoll(c *gin.Context){slug:=c.Param("slug");if !slugPattern.MatchString(slug){fail(c,400,"This poll link is not valid.");return};var p Poll;if err:=s.db.Collection("polls").FindOne(c,bson.M{"slug":slug}).Decode(&p);err!=nil{fail(c,404,"Poll not found.");return};counts,err:=s.getCounts(c,p);if err!=nil{fail(c,503,"Live results are temporarily unavailable.");return};c.JSON(200,gin.H{"poll":p,"counts":counts,"total":sum(counts)})}
func (s *Server) castVote(c *gin.Context) {
	slug := c.Param("slug")
	if !slugPattern.MatchString(slug) { fail(c, 400, "This poll link is not valid."); return }
	var in struct { OptionID string `json:"optionId"`; VoterID string `json:"voterId"` }
	if !decode(c, &in) { return }
	if !optionPattern.MatchString(in.OptionID) { fail(c, 400, "Choose one of the listed answers."); return }
	if len(in.VoterID) < 16 || len(in.VoterID) > 128 || strings.TrimSpace(in.VoterID) != in.VoterID { fail(c, 400, "Your voting session is not valid. Reload and try again."); return }
	var p Poll
	if err := s.db.Collection("polls").FindOne(c, bson.M{"slug": slug}).Decode(&p); err != nil { fail(c, 404, "Poll not found."); return }
	if p.Closed { fail(c, 409, "Voting is closed for this poll."); return }
	valid := false
	for _, o := range p.Options { if o.ID == in.OptionID { valid = true; break } }
	if !valid { fail(c, 400, "Choose one of the listed answers."); return }
	if _, err := s.getCounts(c, p); err != nil { fail(c, 503, "Live results are temporarily unavailable."); return }
	sumHash := sha256.Sum256([]byte(slug + ":" + in.VoterID))
	voterHash := hex.EncodeToString(sumHash[:])
	key := countsKey(slug)
	voteKey := "poll:" + slug + ":voter:" + voterHash
	// One Lua operation deduplicates a session and increments Redis atomically.
	voteScript := redis.NewScript(`if redis.call('SETNX',KEYS[2],1)==0 then return -1 end; return redis.call('HINCRBY',KEYS[1],ARGV[1],1)`)
	result, err := voteScript.Run(c, s.rdb, []string{key, voteKey}, in.OptionID).Int64()
	if err != nil { fail(c, 503, "Live results are temporarily unavailable."); return }
	if result < 0 { fail(c, 409, "You have already voted in this poll."); return }
	vote := Vote{PollID: p.ID, OptionID: in.OptionID, VoterHash: voterHash, CreatedAt: time.Now().UTC()}
	_, err = s.db.Collection("votes").InsertOne(c, vote)
	if err != nil {
		rollback := redis.NewScript(`redis.call('HINCRBY',KEYS[1],ARGV[1],-1); redis.call('DEL',KEYS[2]); return 1`)
		_ = rollback.Run(c, s.rdb, []string{key, voteKey}, in.OptionID).Err()
		if mongo.IsDuplicateKeyError(err) { fail(c, 409, "You have already voted in this poll."); return }
		fail(c, 500, "Could not save your vote."); return
	}
	cached, err := s.rdb.HGetAll(c, key).Result()
	if err != nil { fail(c, 503, "Your vote was saved, but live results are temporarily unavailable."); return }
	counts := map[string]int64{}
	for id, value := range cached { var n int64; if _, err = fmt.Sscan(value, &n); err == nil { counts[id] = n } }
	s.publishResults(c, slug, counts)
	c.JSON(201, gin.H{"counts": counts, "total": sum(counts)})
}
func countsKey(slug string)string{return "poll:"+slug+":counts"}
func (s *Server) getCounts(ctx context.Context,p Poll)(map[string]int64,error){key:=countsKey(p.Slug);cached,err:=s.rdb.HGetAll(ctx,key).Result();if err!=nil{return nil,err};counts:=map[string]int64{};if len(cached)==0{pipeline:=mongo.Pipeline{bson.D{{Key:"$match",Value:bson.M{"pollId":p.ID}}},bson.D{{Key:"$group",Value:bson.M{"_id":"$optionId","count":bson.M{"$sum":1}}}}};cur,e:=s.db.Collection("votes").Aggregate(ctx,pipeline);if e!=nil{return nil,e};var rows []struct{ID string `bson:"_id"`;Count int64 `bson:"count"`};if e=cur.All(ctx,&rows);e!=nil{return nil,e};for _,o:=range p.Options{counts[o.ID]=0};for _,row:=range rows{counts[row.ID]=row.Count};args:=make([]any,0,len(counts)*2);for id,n:=range counts{args=append(args,id,n)};script:=redis.NewScript(`if redis.call('EXISTS',KEYS[1])==0 then for i=1,#ARGV,2 do redis.call('HSET',KEYS[1],ARGV[i],ARGV[i+1]) end end return redis.call('HGETALL',KEYS[1])`);flat,e:=script.Run(ctx,s.rdb,[]string{key},args...).Result();if e!=nil{return nil,e};cached=mapFlat(flat)};for _,o:=range p.Options{if _,ok:=counts[o.ID];!ok{counts[o.ID]=0}};if len(cached)>0{for id,value:=range cached{var n int64;if _,scanErr:=fmt.Sscan(value,&n);scanErr==nil{counts[id]=n}}};return counts,nil}
func mapFlat(value any)map[string]string{out:=map[string]string{};items,ok:=value.([]any);if !ok{return out};for i:=0;i+1<len(items);i+=2{out[fmt.Sprint(items[i])]=fmt.Sprint(items[i+1])};return out}
func (s *Server) writeCounts(ctx context.Context,slug string,counts map[string]int64){args:=make([]any,0,len(counts)*2);for id,n:=range counts{args=append(args,id,n)};script:=redis.NewScript(`if redis.call('EXISTS',KEYS[1])==0 then for i=1,#ARGV,2 do redis.call('HSET',KEYS[1],ARGV[i],ARGV[i+1]) end end return 1`);_ = script.Run(ctx,s.rdb,[]string{countsKey(slug)},args...).Err()}
func sum(m map[string]int64)int64{var total int64;for _,n:=range m{total+=n};return total}
func (s *Server) publish(ctx context.Context,slug string,value any){b,_:=json.Marshal(value);_ = s.rdb.Publish(ctx,"poll:"+slug+":events",b).Err()}
func (s *Server) publishResults(ctx context.Context,slug string,counts map[string]int64){s.publish(ctx,slug,gin.H{"type":"results","counts":counts,"total":sum(counts)})}
var upgrader=websocket.Upgrader{CheckOrigin:func(r *http.Request)bool{return true},ReadBufferSize:1024,WriteBufferSize:4096}
func (s *Server) websocket(c *gin.Context){slug:=c.Param("slug");if !slugPattern.MatchString(slug){fail(c,400,"This poll link is not valid.");return};var p Poll;if err:=s.db.Collection("polls").FindOne(c,bson.M{"slug":slug}).Decode(&p);err!=nil{fail(c,404,"Poll not found.");return};conn,err:=upgrader.Upgrade(c.Writer,c.Request,nil);if err!=nil{return};defer conn.Close();ctx,cancel:=context.WithCancel(c);defer cancel();sub:=s.rdb.Subscribe(ctx,"poll:"+slug+":events");defer sub.Close();if _,err=sub.Receive(ctx);err!=nil{return};counts,err:=s.getCounts(ctx,p);if err!=nil{return};initial,_:=json.Marshal(gin.H{"type":"results","counts":counts,"total":sum(counts)});if conn.WriteMessage(websocket.TextMessage,initial)!=nil{return};for{select{case msg:=<-sub.Channel():if msg==nil{return};if conn.WriteMessage(websocket.TextMessage,[]byte(msg.Payload))!=nil{return};case<-ctx.Done():return}}}





