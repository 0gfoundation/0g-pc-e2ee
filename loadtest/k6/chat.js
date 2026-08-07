// Load driver for the 0G-PC gateway's sealed inference path.
//
// Two modes, and the distinction matters more than any single number:
//
//   MODE=ramp   (default) a staircase of arrival rates, aborting once errors pass
//               1%. This BRACKETS the saturation point — the step where p99
//               latency turns up and errors begin is the gateway's ceiling.
//   MODE=steady one constant arrival rate for DURATION. Once the ramp has told
//               you roughly where the knee is, this is how you get a number you
//               can quote, with a stable p50/p95/p99 behind it.
//
// Both use k6's ARRIVAL-RATE executors, never a fixed pool of VUs. That is
// deliberate: a fixed-VU (closed-loop) test slows its own request rate down as the
// server slows, so the server never actually gets overloaded and the latency
// numbers understate the problem (coordinated omission). An arrival-rate executor
// keeps offering load at the configured rate regardless, which is what a real
// clientele does.
//
// Reading the results:
//   http_req_waiting  — time to response HEADERS. The gateway writes them when the
//                       first sealed frame arrives, so on a streaming run this IS
//                       end-to-end time-to-first-token. It is the number users feel.
//   http_req_duration — the whole exchange; on a streaming run that is dominated by
//                       the fixture's configured token schedule, so it says little
//                       about the gateway until the gateway is the thing that is slow.
//   gateway_failed    — non-2xx, or a 200 whose body is not a well-formed completion
//                       (a mid-stream error event still arrives with a 200 status).
//
// And read them next to the gateway's own metrics — zg_gateway_http_requests_in_flight
// and zg_gateway_completions_total{result,source} on :9464 — which attribute a
// failure to the gateway or to its upstream. The client only ever sees "it broke".

import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';

const GATEWAY_URL = __ENV.GATEWAY_URL || 'http://localhost:8443';
const API_KEY = __ENV.API_KEY || 'sk-loadtest';
const MODEL = __ENV.MODEL || 'mock-model';
const STREAM = (__ENV.STREAM || 'true') !== 'false';
const PROMPT_BYTES = num(__ENV.PROMPT_BYTES, 512);
const MODE = __ENV.MODE || 'ramp';

// Ramp-mode shape.
const START_RATE = num(__ENV.START_RATE, 5);
const PEAK_RATE = num(__ENV.PEAK_RATE, 200);
const STEPS = num(__ENV.STEPS, 8);
const STEP_DURATION = __ENV.STEP_DURATION || '2m';

// Steady-mode shape.
const RATE = num(__ENV.RATE, 25);
const DURATION = __ENV.DURATION || '5m';

// preAllocatedVUs / maxVUs must comfortably exceed rate × request-duration, or k6
// runs out of workers and reports a dropped_iterations count instead of load. A
// streamed completion is held open for its whole token schedule, so this needs to
// be generous — dropped_iterations in the summary means the DRIVER fell short, not
// the gateway.
const MAX_VUS = num(__ENV.MAX_VUS, 2000);

const failed = new Rate('gateway_failed');

export const options = {
  scenarios: MODE === 'steady' ? steadyScenario() : rampScenario(),
  thresholds: {
    // Abort the ramp once the error rate stays over 1%: past that point the extra
    // steps only add noise, and the last healthy step is the answer.
    gateway_failed: [{ threshold: 'rate<0.01', abortOnFail: true, delayAbortEval: '30s' }],
  },
  // Report the percentiles a capacity decision is actually made on.
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
  discardResponseBodies: false,
};

function rampScenario() {
  const stages = [];
  for (let i = 0; i < STEPS; i++) {
    const target = Math.round(START_RATE + ((PEAK_RATE - START_RATE) * i) / Math.max(STEPS - 1, 1));
    // Climb to the step, then hold it: the hold is the measurement, the climb is
    // just getting there.
    stages.push({ target, duration: '15s' });
    stages.push({ target, duration: STEP_DURATION });
  }
  return {
    ramp: {
      executor: 'ramping-arrival-rate',
      startRate: START_RATE,
      timeUnit: '1s',
      preAllocatedVUs: Math.min(MAX_VUS, 200),
      maxVUs: MAX_VUS,
      stages,
    },
  };
}

function steadyScenario() {
  return {
    steady: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: Math.min(MAX_VUS, 200),
      maxVUs: MAX_VUS,
    },
  };
}

// A prompt of a controlled size. Prompt size drives the gateway's per-request seal
// cost (HPKE setup is fixed, the AEAD pass is linear in the payload), so it is a
// knob worth sweeping separately from the request rate.
const PROMPT = 'x'.repeat(Math.max(PROMPT_BYTES, 1));

const params = {
  headers: {
    'Content-Type': 'application/json',
    // The gateway's front-door gate only checks the shape of this; the router
    // (here, the fixture) is what would authenticate it for real.
    Authorization: `Bearer ${API_KEY}`,
  },
  // Well above any completion the fixture is configured to produce. Too low and
  // client-side timeouts get counted as gateway failures.
  timeout: '120s',
  tags: { stream: String(STREAM) },
};

export default function () {
  const body = JSON.stringify({
    model: MODEL,
    messages: [{ role: 'user', content: PROMPT }],
    stream: STREAM,
  });

  const res = http.post(`${GATEWAY_URL}/v1/chat/completions`, body, params);

  // A 200 is not success on its own: a failure after the first frame arrives as an
  // error event inside an otherwise healthy stream, and counting those as OK is how
  // a load test reports a ceiling that is not there.
  const ok = check(res, {
    'status is 200': (r) => r.status === 200,
    'body is a complete response': (r) => (STREAM ? isCompleteStream(r) : isCompleteJSON(r)),
  });
  failed.add(!ok);
}

// A healthy stream ends with `data: [DONE]` and carries no gateway error event.
// The marker is `_0g`, not `error`: the gateway's error envelope always includes
// that sibling attribution block (openaiproxy.errorEnvelope), and unlike "error"
// it cannot collide with generated content that happens to contain the word.
function isCompleteStream(res) {
  const body = res.body || '';
  return body.includes('data: [DONE]') && !body.includes('"_0g"');
}

function isCompleteJSON(res) {
  try {
    const parsed = JSON.parse(res.body);
    return Array.isArray(parsed.choices) && parsed.choices.length > 0 && !parsed.error;
  } catch (_) {
    return false;
  }
}

function num(v, def) {
  const n = Number(v);
  return v === undefined || v === '' || Number.isNaN(n) ? def : n;
}
