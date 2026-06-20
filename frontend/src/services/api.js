import axios from 'axios';

const BASE_URL = window.location.port === '5173' ? 'http://localhost:5000/api' : '/api';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
});

// ── Scan endpoints ───────────────────────────────────────────────────────────

export const scanManual = (payload) =>
  api.post('/scan/manual', { payload }).then((r) => r.data);

export const scanUpload = (formData) =>
  api.post('/scan/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 60000,
  }).then((r) => r.data);

export const scanLive = (payload) =>
  api.post('/scan/live', { payload }).then((r) => r.data);

// ── History endpoints ────────────────────────────────────────────────────────

export const getHistory = (page = 1, limit = 20) =>
  api.get('/history/', { params: { page, limit } }).then((r) => r.data);

export const deleteHistoryItem = (id) =>
  api.delete(`/history/${id}`).then((r) => r.data);

// ── Analytics ────────────────────────────────────────────────────────────────

export const getAnalytics = () =>
  api.get('/history/analytics').then((r) => r.data);

// ── Crypto endpoints ─────────────────────────────────────────────────────────

export const verifySignature = (data) =>
  api.post('/verify-signature', data).then((r) => r.data);

export const decryptPayload = (data) =>
  api.post('/decrypt', data).then((r) => r.data);

// ── Health ───────────────────────────────────────────────────────────────────

export const healthCheck = () =>
  api.get('/health').then((r) => r.data);

// ── Intelligence endpoints ───────────────────────────────────────────────────

export const getIntelligenceSummary = () =>
  api.get('/intelligence/summary').then((r) => r.data);

export const getCampaigns = () =>
  api.get('/intelligence/campaigns').then((r) => r.data);

export const getGraphSnapshot = (limit = 200) =>
  api.get('/intelligence/graph', { params: { limit } }).then((r) => r.data);

export const getTopCampaigns = () =>
  api.get('/intelligence/top-campaigns').then((r) => r.data);

export const getGraphStats = () =>
  api.get('/intelligence/graph/stats').then((r) => r.data);

export const getCampaignAttribution = (id) =>
  api.get(`/intelligence/attribution/${id}`).then((r) => r.data);

export const getForecasts = () =>
  api.get('/intelligence/forecasts').then((r) => r.data);

export const getCampaignForecast = (campaignId) =>
  api.get(`/intelligence/forecast/${campaignId}`).then((r) => r.data);

export const runForecasts = () =>
  api.post('/intelligence/forecast/run').then((r) => r.data);

export const getForecastValidation = () =>
  api.get('/forecast/validation').then((r) => r.data);

export const getEvaluationResults = () =>
  api.get('/intelligence/evaluation/results').then((r) => r.data);

export const runEvaluationBenchmark = () =>
  api.post('/intelligence/evaluation/run').then((r) => r.data);

export default api;


