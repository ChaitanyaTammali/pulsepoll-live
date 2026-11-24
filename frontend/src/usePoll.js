import { useCallback, useEffect, useState } from 'react'
import { request, socketURL } from './api'

export function usePoll(slug) {
  const [poll, setPoll] = useState(null), [counts, setCounts] = useState(null), [total, setTotal] = useState(0), [connected, setConnected] = useState(false), [error, setError] = useState(''), [voted, setVoted] = useState(() => localStorage.getItem(`pulse_voted_${slug}`) === '1')
  const refresh = useCallback(async () => { try { const data = await request(`/polls/${slug}`); setPoll(data.poll); setCounts(data.counts); setTotal(data.total); setError('') } catch (e) { setError(e.message) } }, [slug])
  useEffect(() => { setPoll(null); setVoted(localStorage.getItem(`pulse_voted_${slug}`) === '1'); refresh(); let socket, retry, stopped = false; const connect = () => { if (stopped) return; socket = new WebSocket(socketURL(slug)); socket.onopen = () => setConnected(true); socket.onmessage = event => { try { const data = JSON.parse(event.data); if (data.type === 'results') { setCounts(data.counts); setTotal(data.total) } if (data.type === 'poll') setPoll(data.poll) } catch {} }; socket.onclose = () => { setConnected(false); if (!stopped) retry = setTimeout(connect, 1800) }; socket.onerror = () => socket.close() }; connect(); return () => { stopped = true; clearTimeout(retry); socket?.close() } }, [slug, refresh])
  const castVote = useCallback(async optionId => { const voterId = localStorage.getItem('pulse_voter') || crypto.randomUUID(); localStorage.setItem('pulse_voter', voterId); await request(`/polls/${slug}/votes`, { method: 'POST', body: JSON.stringify({ optionId, voterId }) }); localStorage.setItem(`pulse_voted_${slug}`, '1'); setVoted(true); await refresh() }, [slug, refresh])
  return { poll, counts: counts || {}, total, connected, error, castVote, voted }
}
