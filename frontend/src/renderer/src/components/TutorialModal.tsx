// User tutorial component, shows on the first load of the app, allows preference selection and a guided
// widget-by-widget walkthrough of the dashboard.

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import './TutorialModal.css';

type Phase = 'welcome' | 'preference' | 'tour';

interface Rect {
  top: number;
  left: number;
  width: number;
  height: number;
}

interface CardPos {
  top: number;
  left: number;
  width: number;
}

interface WidgetStep {
  id: string;
  title: string;
  targets: string[];
}

const WIDGET_STEPS: WidgetStep[] = [
  {
    id: 'capture-trend',
    title: 'Packet Capture & Threat Trend',
    targets: ['tutorial-capture', 'tutorial-trend'],
  },
  {
    id: 'detection-stats',
    title: 'Detection Statistics',
    targets: ['tutorial-detection-stats'],
  },
  {
    id: 'signatures',
    title: 'Signature Detection',
    targets: ['tutorial-signatures'],
  },
  {
    id: 'rules',
    title: 'Rule Performance',
    targets: ['tutorial-rules'],
  },
  {
    id: 'alerts',
    title: 'Alert Log',
    targets: ['tutorial-alerts'],
  },
];

const SCROLL_CONTAINER_SELECTOR = '.dashboard-grid';
const SPOTLIGHT_PADDING = 10;
const CARD_WIDTH = 340;
const CARD_MARGIN = 20;
const CARD_RIGHT_MARGIN = 48;
const CARD_EST_HEIGHT = 230;
const FADE_OUT_MS = 550;
const SCROLL_DURATION_MS = 950;
const MEASURE_BUFFER_MS = 100;
const CLOSE_FADE_MS = 850;

function easeInOutCubic(t: number): number {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

// scrolls to specific scroll coodinate
function animateScrollTo(container: HTMLElement, targetTop: number, duration: number) {
  const startTop = container.scrollTop;
  const delta = targetTop - startTop;
  if (Math.abs(delta) < 1) return;
  const startTime = performance.now();

  const step = (now: number) => {
    const t = Math.min(1, (now - startTime) / duration);
    container.scrollTop = startTop + delta * easeInOutCubic(t);
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), Math.max(min, max));
}

// maps the highlight of the widgets being observed by the steps
function getUnionRect(ids: string[]): Rect | null {
  const rects = ids
    .map((id) => document.getElementById(id)?.getBoundingClientRect())
    .filter((r): r is DOMRect => !!r);
  if (rects.length === 0) return null;
  const top = Math.min(...rects.map((r) => r.top));
  const left = Math.min(...rects.map((r) => r.left));
  const right = Math.max(...rects.map((r) => r.right));
  const bottom = Math.max(...rects.map((r) => r.bottom));
  return { top, left, width: right - left, height: bottom - top };
}

// scrolls to certain section to allow full view of widget
function scrollTargetsIntoView(ids: string[]) {
  const container = document.querySelector(SCROLL_CONTAINER_SELECTOR) as HTMLElement | null;
  const rect = getUnionRect(ids);
  if (!container || !rect) return;
  const viewportCenter = window.innerHeight / 2;
  const rectCenter = rect.top + rect.height / 2;
  animateScrollTo(container, container.scrollTop + (rectCenter - viewportCenter), SCROLL_DURATION_MS);
}

function computeCardPos(rect: Rect): CardPos {
  const vw = window.innerWidth;
  const vh = window.innerHeight;

  const spaceRight = vw - (rect.left + rect.width);
  const spaceLeft = rect.left;
  const spaceBelow = vh - (rect.top + rect.height);

  let top: number;
  let left: number;
// horrible but gets the job done lol
  if (spaceRight >= CARD_WIDTH + CARD_RIGHT_MARGIN) {
    left = Math.min(rect.left + rect.width + CARD_MARGIN, vw - CARD_WIDTH - CARD_RIGHT_MARGIN);
    top = clamp(rect.top + rect.height / 2 - CARD_EST_HEIGHT / 2, CARD_MARGIN, vh - CARD_EST_HEIGHT - CARD_MARGIN);
  } else if (spaceLeft >= CARD_WIDTH + CARD_MARGIN) {
    left = rect.left - CARD_WIDTH - CARD_MARGIN;
    top = clamp(rect.top + rect.height / 2 - CARD_EST_HEIGHT / 2, CARD_MARGIN, vh - CARD_EST_HEIGHT - CARD_MARGIN);
  } else if (spaceBelow >= CARD_EST_HEIGHT + CARD_MARGIN) {
    top = rect.top + rect.height + CARD_MARGIN;
    left = clamp(rect.left + rect.width / 2 - CARD_WIDTH / 2, CARD_MARGIN, vw - CARD_WIDTH - CARD_RIGHT_MARGIN);
  } else {
    top = Math.max(CARD_MARGIN, rect.top - CARD_EST_HEIGHT - CARD_MARGIN);
    left = clamp(rect.left + rect.width / 2 - CARD_WIDTH / 2, CARD_MARGIN, vw - CARD_WIDTH - CARD_RIGHT_MARGIN);
  }

  return { top, left, width: CARD_WIDTH };
}

const TutorialModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const { theme, setTheme } = useTheme();
  const [phase, setPhase] = useState<Phase>('welcome');
  const [tourIndex, setTourIndex] = useState(0);
  const [highlightRect, setHighlightRect] = useState<Rect | null>(null);
  const [stepVisible, setStepVisible] = useState(false);
  const [cardPos, setCardPos] = useState<CardPos | null>(null);
  const [closing, setClosing] = useState(false);

  const timers = useRef<number[]>([]);

  const clearTimers = () => {
    timers.current.forEach((t) => window.clearTimeout(t));
    timers.current = [];
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Lock scrolling while we are in the 'tour'
  useEffect(() => {
    const container = document.querySelector(SCROLL_CONTAINER_SELECTOR) as HTMLElement | null;
    if (!container || phase !== 'tour') return undefined;
    const prevOverflow = container.style.overflowY;
    container.style.overflowY = 'hidden';
    return () => {
      container.style.overflowY = prevOverflow;
    };
  }, [phase]);

  // this part was ass literally, synchonisouly changes position of card, highlight, and position
  // of scrolling
  useEffect(() => {
    if (phase !== 'tour') return undefined;
    let cancelled = false;
    clearTimers();
    setStepVisible(false);

    const step = WIDGET_STEPS[tourIndex];
    scrollTargetsIntoView(step.targets);

    const t1 = window.setTimeout(() => {
      if (cancelled) return;
      const rect = getUnionRect(step.targets);
      if (rect) {
        setHighlightRect(rect);
        setCardPos(computeCardPos(rect));
      }
      const t2 = window.setTimeout(() => {
        if (!cancelled) setStepVisible(true);
      }, 20);
      timers.current.push(t2);
    }, Math.max(FADE_OUT_MS, SCROLL_DURATION_MS) + MEASURE_BUFFER_MS);
    timers.current.push(t1);

    return () => {
      cancelled = true;
      clearTimers();
    };
  }, [phase, tourIndex]);

  useEffect(() => {
    if (phase !== 'tour') return undefined;
    const onResize = () => {
      const step = WIDGET_STEPS[tourIndex];
      const rect = getUnionRect(step.targets);
      if (rect) {
        setHighlightRect(rect);
        setCardPos(computeCardPos(rect));
      }
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [phase, tourIndex]);

  useEffect(() => clearTimers, []);

  // next functions start, end, and move tutorial through steps

  const startTour = useCallback(() => {
    setTourIndex(0);
    setPhase('tour');
  }, []);

  const finishTour = useCallback(() => {
    if (closing) return;
    setClosing(true);
    setStepVisible(false);
    const t = window.setTimeout(() => onClose(), CLOSE_FADE_MS);
    timers.current.push(t);
  }, [closing, onClose]);

  const handleNext = useCallback(() => {
    if (tourIndex < WIDGET_STEPS.length - 1) {
      setTourIndex((i) => i + 1);
    } else {
      finishTour();
    }
  }, [tourIndex, finishTour]);

  const handleBack = useCallback(() => {
    if (tourIndex > 0) {
      setTourIndex((i) => i - 1);
    } else {
      setPhase('preference');
    }
  }, [tourIndex]);

  const step = WIDGET_STEPS[tourIndex];

  return (
    <>
      {phase !== 'tour' && (
        <div className="tutorial-modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
          <div className="tutorial-modal">
            {phase === 'welcome' && (
              <div className="tutorial-modal-step" key="step-welcome">
                <h3 className="tutorial-modal-title-centered">Welcome!</h3>
                <p className="tutorial-modal-subtext-centered">
                  Since you're new here, we recommend taking a quick tour of the app to get started!
                </p>
                <button className="auth-submit tutorial-modal-confirm" onClick={() => setPhase('preference')}>
                  Next
                </button>
                <button className="tutorial-modal-skip" onClick={onClose}>
                  No thanks, I'll explore on my own
                </button>
              </div>
            )}

            {phase === 'preference' && (
              <div className="tutorial-modal-step" key="step-preference">
                <h3 className="tutorial-modal-title-centered">Lighting Preference</h3>
                <p className="tutorial-modal-subtext-centered">Choose your preferred lighting mode</p>

                <div className="theme-picker-row">
                  <div className="theme-picker-option">
                    <div
                      className="theme-preview theme-preview-light"
                      onClick={() => setTheme('light')}
                      role="button"
                      aria-label="Preview light mode"
                    >
                      <span className="theme-preview-widget" />
                      <span className="theme-preview-widget" />
                      <span className="theme-preview-widget theme-preview-widget-wide" />
                    </div>
                    <button
                      type="button"
                      className={`theme-picker-radio ${theme === 'light' ? 'selected' : ''}`}
                      aria-label="Select light mode"
                      onClick={() => setTheme('light')}
                    />
                    <span className="theme-picker-label"></span>
                  </div>

                  <div className="theme-picker-option">
                    <div
                      className="theme-preview theme-preview-dark"
                      onClick={() => setTheme('dark')}
                      role="button"
                      aria-label="Preview dark mode"
                    >
                      <span className="theme-preview-widget" />
                      <span className="theme-preview-widget" />
                      <span className="theme-preview-widget theme-preview-widget-wide" />
                    </div>
                    <button
                      type="button"
                      className={`theme-picker-radio ${theme === 'dark' ? 'selected' : ''}`}
                      aria-label="Select dark mode"
                      onClick={() => setTheme('dark')}
                    />
                    <span className="theme-picker-label"></span>
                  </div>
                </div>

                <button className="auth-submit tutorial-modal-confirm" onClick={startTour}>
                  Confirm
                </button>
                <button className="tutorial-modal-skip" onClick={onClose}>
                  No thanks, I'll explore on my own
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {phase === 'tour' && (
        <>
          <div className="tutorial-tour-blocker" />

          {highlightRect && (
            <div
              className={`tutorial-spotlight ${stepVisible ? 'visible' : ''}`}
              style={{
                top: highlightRect.top - SPOTLIGHT_PADDING,
                left: highlightRect.left - SPOTLIGHT_PADDING,
                width: highlightRect.width + SPOTLIGHT_PADDING * 2,
                height: highlightRect.height + SPOTLIGHT_PADDING * 2,
              }}
            />
          )}

          {cardPos && (
            <div
              className={`tutorial-tour-card ${stepVisible ? 'visible' : ''}`}
              style={{ top: cardPos.top, left: cardPos.left, width: cardPos.width }}
            >
              <div className="tutorial-tour-dots">
                {WIDGET_STEPS.map((s, i) => (
                  <span key={s.id} className={i === tourIndex ? 'active' : ''} />
                ))}
              </div>

              <h3 className="tutorial-tour-title">{step.title}</h3>

              <div className="tutorial-tour-actions">
                <button className="tutorial-tour-skip" onClick={onClose}>
                  Skip tour
                </button>
                <div className="tutorial-tour-nav">
                  <button className="tutorial-tour-back" onClick={handleBack}>
                    Back
                  </button>
                  <button className="auth-submit tutorial-tour-next" onClick={handleNext}>
                    {tourIndex === WIDGET_STEPS.length - 1 ? 'Finish' : 'Next'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </>
  );
};

export default TutorialModal;
