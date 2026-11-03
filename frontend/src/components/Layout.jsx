import { NavLink, Outlet, useLocation } from 'react-router-dom';
import ErrorBoundary from './ErrorBoundary.jsx';
import { InfoIcon } from './Icons.jsx';
import { USE_MOCK } from '../api/assessUrl.js';
import bannerImage from '../assets/phishcheck-banner.png';

const BANNER_ALT =
  'PhishCheck: paste a link, get a trust score, learn what to look for. ' +
  'Assignment 3, COS30049, by Alyssa K (103073209) and Takis M (105930092).';

export default function Layout() {
  const { pathname } = useLocation();

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>

      <header className="site-header">
        <div className="site-banner">
          <img src={bannerImage} alt={BANNER_ALT} width="1139" height="353" className="site-banner__image" />
        </div>
        <nav aria-label="Main" className="site-nav">
          <ul className="container nav-list">
            <li>
              <NavLink to="/" end className="nav-link">
                Check a URL
              </NavLink>
            </li>
            <li>
              <NavLink to="/history" className="nav-link">
                History
              </NavLink>
            </li>
          </ul>
        </nav>
      </header>

      {USE_MOCK && (
        <div className="demo-banner" role="note">
          <div className="container">
            <InfoIcon size={18} />
            <span>
              <strong>Demo mode:</strong> results are simulated in your browser, not produced by the trained model.
            </span>
          </div>
        </div>
      )}

      <main id="main" tabIndex={-1} className="site-main">
        <ErrorBoundary resetKey={pathname}>
          <Outlet />
        </ErrorBoundary>
      </main>

      <footer className="site-footer">
        <div className="container">
          <p>COS30049 Computing Technology Innovation Project · Alyssa Kades and Takis Michailaros</p>
        </div>
      </footer>
    </div>
  );
}
