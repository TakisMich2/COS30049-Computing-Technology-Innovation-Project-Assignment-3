"""Start the PhishCheck server:  python run.py  (settings come from backend/.env)."""

import logging
import os

import uvicorn

from app.config import Settings
from app.main import create_app

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    settings = Settings()
    uvicorn.run(
        create_app(settings),
        host=os.getenv('HOST', '127.0.0.1'),
        port=int(os.getenv('PORT', '8000')),
        server_header=not settings.defence_enabled('hardening'),  # don't advertise the server software
        proxy_headers=False,
        access_log=False,      # our own request log never records submitted URLs
        log_level='info',
    )
