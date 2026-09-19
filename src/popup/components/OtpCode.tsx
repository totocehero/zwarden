/**
 * @file One-time code: the countdown ring, and the heartbeat.
 *
 * ## Why the heartbeat lives here and not in `App`
 *
 * The code recomputes every second. While that state lived in `App`, every beat
 * re-rendered the whole popup — filtering the entire vault and diffing the
 * complete tree, once a second. Confining it to the component that displays it
 * means the beat re-renders only that component.
 *
 * ## Recomputed, never counted down
 *
 * A JavaScript timer drifts, and the popup can be frozen by the browser.
 * Re-reading the clock on every beat guarantees a displayed code really is the
 * current window's — showing a stale code would be worse than showing none.
 */

import { useEffect, useState } from 'preact/hooks';

import { t } from '@shared/i18n.js';
import { type TotpConfig, formatTotp, generateTotp, secondsRemaining } from '@core/vault/totp.js';

/**
 * Countdown ring for the one-time code.
 *
 * A number of seconds gets read; a gauge gets seen. Since the code is copied
 * under time pressure, the "I have enough left" signal must land out of the
 * corner of the eye, without reading. The ring empties, and the figure stays in
 * the middle for whoever wants the exact value.
 *
 * @param remaining Seconds left.
 * @param period Total window length, for the scale.
 */
export function OtpRing({ remaining, period }: { remaining: number; period: number }) {
  const radius = 8;
  const circumference = 2 * Math.PI * radius;
  const share = Math.max(0, Math.min(1, remaining / period));
  const urgent = remaining <= 5;

  return (
    <svg
      class={`ring${urgent ? ' anneau-urgent' : ''}`}
      width="22"
      height="22"
      viewBox="0 0 22 22"
      aria-hidden="true"
    >
      {/* Track: the empty ring stays visible, otherwise the gauge seems to vanish. */}
      <circle cx="11" cy="11" r={radius} fill="none" stroke="currentColor" stroke-width="2" opacity="0.22" />
      <circle
        cx="11"
        cy="11"
        r={radius}
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-dasharray={circumference}
        stroke-dashoffset={circumference * (1 - share)}
        // Starting at noon, clockwise: the way a clock is read.
        transform="rotate(-90 11 11)"
      />
      <text x="11" y="11" class="ring-text" text-anchor="middle" dominant-baseline="central">
        {remaining}
      </text>
    </svg>
  );
}

/**
 * An item's one-time code, with its countdown.
 *
 * ## Why the first code is handed in rather than computed
 *
 * The caller copies the code to the clipboard the moment it opens this panel.
 * If this component computed its own first value, the two computations would sit
 * a few milliseconds apart — and a few milliseconds astride a window boundary
 * are enough for them to fall in different windows. The user would then read one
 * code and paste another: a silent failure, and one the site gets blamed for.
 *
 * So the value is computed once, by the caller, and handed in. Afterwards this
 * component recomputes on its own every second, where there is only one reader.
 *
 * @param config Resolved parameters, already decrypted by the caller: this
 *   component never touches the vault.
 * @param initialCode The code the caller computed and copied.
 * @param onCopy Copies the code — the caller adds its own visual feedback.
 * @param copied True briefly after a copy.
 */
export function OtpCode({
  config,
  initialCode,
  onCopy,
  copied,
}: {
  config: TotpConfig;
  initialCode: string;
  onCopy: (code: string) => void;
  copied: boolean;
}) {
  const [code, setCode] = useState(initialCode);
  const [remaining, setRemaining] = useState(() => secondsRemaining(config));

  useEffect(() => {
    let alive = true;
    const beat = async (): Promise<void> => {
      const computed = await generateTotp(config);
      if (alive) {
        setCode(computed);
        setRemaining(secondsRemaining(config));
      }
    };
    // No immediate beat: `initialCode` is already the current window's value, and
    // recomputing it here would reintroduce the very divergence this component
    // exists to avoid.
    const timer = setInterval(() => void beat(), 1000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [config]);

  if (code === '') {
    return null;
  }

  return (
    <div class="otp" title={t('otpCopy')} onClick={() => onCopy(code)}>
      <span class="otp-code">{formatTotp(code)}</span>
      <span class="otp-end">
        {copied && <span class="otp-copied">{t('otpCopied')}</span>}
        <OtpRing remaining={remaining} period={config.period} />
      </span>
    </div>
  );
}
