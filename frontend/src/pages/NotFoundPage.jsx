import { Link, useLocation } from 'react-router-dom';
import usePageTitle from '../hooks/usePageTitle.js';
import { SearchIcon } from '../components/Icons.jsx';

export default function NotFoundPage() {
  usePageTitle('Page not found');
  const { pathname } = useLocation();

  return (
    <section className="status-page container" aria-labelledby="not-found-title">
      <span className="status-page__icon" aria-hidden="true">
        <SearchIcon />
      </span>
      <p className="status-page__code">Error 404</p>
      <h1 id="not-found-title">We couldn’t find that page</h1>
      <p className="status-page__text">
        There is no page at <code className="inline-code">{pathname}</code>. The link may be out of date or
        mistyped.
      </p>
      <div className="button-row">
        <Link className="button button--primary" to="/">
          Check a URL
        </Link>
        <Link className="button button--secondary" to="/history">
          View your history
        </Link>
      </div>
    </section>
  );
}
