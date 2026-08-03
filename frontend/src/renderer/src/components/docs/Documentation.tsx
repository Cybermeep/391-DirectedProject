import React, { useEffect, useRef, useState } from 'react';
import confusionMatrixImg from '../../assets/confusion_matrix.png';
import featureImportanceImg from '../../assets/feature_importance.png';
import './Docs.css';

interface FaqItem {
  id: string;
  question: string;
  answer: React.ReactNode;
}

interface FaqCategory {
  id: string;
  label: string;
  items: FaqItem[];
}

const CATEGORIES: FaqCategory[] = [
  {
    id: 'about-homenids',
    label: 'About HomiNIDS',
    items: [
      {
        id: 'what-does-homenids-do',
        question: 'What does HomiNIDS do?',
        answer: (
          <p>
            HomiNIDS parses network traffic and uses rules to alert on common attack signatures. It
            includes a dashboard with graphs of important data, an interface to toggle rules on and
            off, and the option to create your own custom rules.
          </p>
        ),
      },
      {
        id: 'how-is-it-different',
        question: 'How is HomiNIDS different from other NIDS?',
        answer: (
          <p>
            HomiNIDS is designed to be user-friendly and easy to use, built for newcomers and
            learners rather than security professionals. It also includes an AI model set up to
            detect and alert on suspicious network traffic alongside the rule-based detection.
          </p>
        ),
      },
      {
        id: 'can-it-block-traffic',
        question: 'Can HomiNIDS block traffic as well?',
        answer: (
          <p>
            No, HomiNIDS is a detection system, not a prevention system, so it doesn't block traffic
            on its own. What it's able to see (and therefore alert on) depends on where it's placed
            in your network.
          </p>
        ),
      },
      {
        id: 'what-to-do-with-alerts',
        question: 'What should I do with the alerts?',
        answer: (
          <p>
            Each alert shows the reason it was flagged. From there it's up to you to decide what
            action to take. HomiNIDS displays the information but doesn't act on it for you.
          </p>
        ),
      },
      {
        id: 'no-cli-needed',
        question: 'Do I need to know how to use the command line to use HomiNIDS?',
        answer: (
          <p>
            No. HomiNIDS is a complete application with a user-friendly front end already built in.
            The different subscription tiers unlock features that extend what the app can do and
            improve the overall experience, but none of them require the command line.
          </p>
        ),
      },
    ],
  },
  {
    id: 'getting-started',
    label: 'Getting started',
    items: [
      {
        id: 'what-is-this',
        question: 'What does this application do?',
        answer: (
          <p>
            <strong>HomiNIDS</strong> parses through network traffic and uses rules to alert on common attack signatures. It includes a dashboard with graphs of important data, and an interface to toggle rules. There is also an option to create custom rules.
          </p>
        ),
      },
      {
        id: 'how-to-start-capture',
        question: 'How do I start capturing traffic?',
        answer: (
          <p>
            From the Dashboard, use the interface picker (backed by{' '}
            <code>/api/capture/interfaces</code>) to choose a network adapter, then start capture. On
            Windows this requires <strong>Npcap</strong> to be installed and the backend to be running
            with Administrator privileges.
          </p>
        ),
      }
    ],
  },
  {
    id: 'detection',
    label: 'Detection methods',
    items: [
      {
        id: 'signatures-vs-rules',
        question: 'What is the difference between built-in signatures and custom rules?',
        answer: (
          <p>
            Our 30 built-in signatures are pre-made rules that detect common attack patterns.
             Custom rules are user-defined boolean expressions over a whitelisted set of fields, 
             allowing you to create your own detection logic.
          </p>
        ),
      },
      {
        id: 'how-confident-is-ml',
        question: 'How reliable is the ML confidence score on live traffic?',
        answer: (
          <>
            <p>
              The ML model was trained on a dataset of labeled traffic, so the confidence score is
              only as reliable as the model's training. It can be a useful indicator, but it should not
              be treated as a definitive measure of whether traffic is malicious or benign.
            </p>
            <p className="docs-img-caption-lead">
              These are the actual evaluation results from this model's training run, not
              illustrative examples:
            </p>
            <figure className="docs-figure">
              <img src={confusionMatrixImg} alt="Confusion matrix from the trained model's evaluation" className="docs-img" />
              <figcaption>Confusion matrix - how the model's predictions compared to known-correct labels on the held-out test set.</figcaption>
            </figure>
            <figure className="docs-figure">
              <img src={featureImportanceImg} alt="Feature importance chart from the trained model" className="docs-img" />
              <figcaption>Feature importance - which of the 78 flow features the model relied on most when making a prediction.</figcaption>
            </figure>
          </>
        ),
      }
    ],
  },
  {
    id: 'deployment',
    label: 'Deployment & network',
    items: [
      {
        id: 'where-to-place',
        question: 'Where should this application be placed in my network?',
        answer: (
          <p>
            Placement depends on what you want it to cover. You can run it on a device endpoint
            (laptop, PC, etc.), where it will only see traffic destined for that device. It can also
            run on a network device such as an open-source router that supports third-party
            applications. Or you can run it on an endpoint and feed it traffic from a wider part of
            the network using a network tap or port mirroring.
          </p>
        ),
      },
      {
        id: 'will-it-slow-network',
        question: 'Will this application slow down my network?',
        answer: (
          <p>
            HomiNIDS uses passive detection, so under normal conditions it won't slow down network
            traffic. Placement matters, though: on a network device, resource use scales with the
            number of active rules and the volume of traffic, and setups that rely on a network tap
            or port mirroring add extra resource consumption on that device — which can affect
            performance.
          </p>
        ),
      },
    ],
  },
  {
    id: 'rules',
    label: 'Rule builder',
    items: [
      {
        id: 'rule-syntax',
        question: 'How do I write a custom rule?',
        answer: (
          <div>
            <p>
              Rules are simple boolean expressions over a whitelisted set of flow fields, for example:
            </p>
            <code className="docs-code-block">
              SYN_Flag_Cnt &gt; 5 AND RST_Flag_Cnt &gt; 3 AND Flow_Byts/s &gt; 1000
            </code>
            <p>
              The Rule Builder validates the expression as you type against the field whitelist, so
              typos or unsupported fields are caught before you save.
            </p>
          </div>
        ),
      }
    ],
  },
  {
    id: 'billing',
    label: 'Plans & billing',
    items: [
      {
        id: 'plan-differences',
        question: 'What do the paid plans unlock?',
        answer: (
          <p>
            <strong>Free</strong> covers core detection, real-time alerts, and 7 days of alert
            history. <strong>Pro</strong> extends history to 30 days and adds the AI Detection
            panel (live model stats and accuracy) plus CSV data export. <strong>Enterprise</strong>{' '}
            extends history to 365 days and adds the custom Rule Builder, letting you write your
            own AST-validated detection rules.
          </p>
        ),
      }
    ],
  },
  {
    id: 'account',
    label: 'Account & privacy',
    items: [
    ],
  },
];

const Documentation: React.FC = () => {
  const [activeId, setActiveId] = useState<string>('');
  const itemRefs = useRef<Record<string, HTMLElement | null>>({});

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting);
        if (visible.length === 0) return;
        const topmost = visible.reduce((a, b) => (a.boundingClientRect.top < b.boundingClientRect.top ? a : b));
        setActiveId(topmost.target.id);
      },
      { rootMargin: '-64px 0px -70% 0px', threshold: 0 }
    );
    Object.values(itemRefs.current).forEach((el) => el && observer.observe(el));
    return () => observer.disconnect();
  }, []);

  const scrollToItem = (id: string) => {
    itemRefs.current[id]?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className="docs-page">
      <div className="docs-header">
        <h2>Documentation &amp; FAQ</h2>
        <p>Answers to common questions about detection, rules, billing, and your data.</p>
      </div>

      <div className="docs-layout">
        <aside className="docs-toc">
          <nav className="docs-toc-nav">
            {CATEGORIES.map((cat) => (
              <div key={cat.id} className="docs-toc-group">
                <div className="docs-toc-category">{cat.label}</div>
                <ul>
                  {cat.items.map((item) => (
                    <li key={item.id}>
                      <button
                        className={`docs-toc-link ${activeId === item.id ? 'active' : ''}`}
                        onClick={() => scrollToItem(item.id)}
                      >
                        {item.question}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
        </aside>

        <div className="docs-content">
          {CATEGORIES.map((cat) => (
            <section key={cat.id} className="docs-category">
              <h3>{cat.label}</h3>
              <div className="docs-list">
                {cat.items.map((item) => (
                  <div
                    key={item.id}
                    id={item.id}
                    ref={(el) => {
                      itemRefs.current[item.id] = el;
                    }}
                    className="docs-item"
                  >
                    <h4 className="docs-question">{item.question}</h4>
                    <div className="docs-answer">{item.answer}</div>
                  </div>
                ))}
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Documentation;
