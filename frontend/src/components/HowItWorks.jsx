const STEPS = [
  {
    title: 'Paste a link',
    text: 'Copy the address from an email, text message or website and paste it above. We never open or visit the link.',
  },
  {
    title: 'Get a trust score',
    text: 'Our model scores the address from 0 to 100. Below 30 is likely phishing; 70 and above is likely safe.',
  },
  {
    title: 'Learn what to look for',
    text: 'Each warning names the suspicious part of the address and explains why, so you can spot it yourself next time.',
  },
];

/** Full-width orange band explaining the three steps, shown under the checker. */
export default function HowItWorks() {
  return (
    <section className="feature-band" aria-labelledby="how-it-works-title">
      <div className="container">
        <div className="feature-band__head">
          <h2 id="how-it-works-title" className="feature-band__title">
            How PhishCheck works
          </h2>
          <svg className="feature-band__arrow" viewBox="0 0 72 72" aria-hidden="true" focusable="false">
            <path d="M70 2 2 70M2 14v56h56" fill="none" stroke="currentColor" strokeWidth="3" />
          </svg>
        </div>
        <ol className="feature-band__list">
          {STEPS.map((step) => (
            <li key={step.title} className="feature-band__item">
              <h3 className="feature-band__item-title">{step.title}</h3>
              <p className="feature-band__item-text">{step.text}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
