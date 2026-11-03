import { CheckIcon } from './Icons.jsx';

const capitalise = (text) => text.charAt(0).toUpperCase() + text.slice(1);

/** Plain-language explanation for every suspicious URL part (FR3, FR5). */
export default function WarningList({ warnings }) {
  return (
    <section className="card warnings" aria-labelledby="warnings-title">
      <h2 id="warnings-title" className="section-title">
        What we found {warnings.length > 0 && <span className="count-badge">{warnings.length}</span>}
      </h2>

      {warnings.length === 0 ? (
        <p className="empty-note">
          <CheckIcon size={20} />
          No suspicious URL patterns were found in this address.
        </p>
      ) : (
        <ul className="warning-list">
          {warnings.map((warning, index) => {
            // "Overall" warnings describe the whole URL in a sentence rather than quoting a part of it.
            const isOverall = warning.part.startsWith('overall');
            return (
              <li key={`${warning.part}-${warning.text}-${index}`} className="warning-item">
                <div className="warning-item__head">
                  <span className="tag">{capitalise(warning.part)}</span>
                  {!isOverall && <code className="warning-item__text mono break">{warning.text}</code>}
                </div>
                <p className="warning-item__reason">{isOverall ? `${warning.text} ${warning.reason}` : warning.reason}</p>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
