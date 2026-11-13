# Visual assets

This academic prototype adapts Equifax's visual theme for an internal vulnerability assurance workspace. It does not reproduce the consumer website's page structure or product content.

Reference reviewed: https://www.equifax.com/ (13 November 2026).

Brand reference stylesheet: https://assets.equifax.com/global/css/efx-gcs.css

- Burgundy `#981E32`, charcoal `#333E48`, teal `#007298` and pale grey `#F1F4F5` come from the reference stylesheet. Status colours continue to distinguish failures, warnings and healthy controls.
- `equifax-logo.svg`: https://assets.equifax.com/global/images/logos/equifax_150_28.svg. Equifax's mark is used to identify the case study client.
- `fonts/OpenSans-{Regular,Semibold,Bold}.woff`: https://assets.equifax.com/global/fonts/ (matching filenames). Open Sans is distributed under the SIL Open Font License; see `fonts/OFL.txt`.

The logo and fonts are bundled locally. The interface embeds the fonts and serves the logo through Streamlit, so these assets do not require a browser connection to Equifax or Google Fonts. This supports an eventual internal installation, but the app remains a session-based academic demonstration rather than a production deployment.

Shared presentation helpers live in `ui.py`; app styles live in `theme.css`; native widget colours live in `.streamlit/config.toml`. Streamlit's semantic `data-testid` selectors are used for a few visual overrides, which should be checked when upgrading Streamlit.
