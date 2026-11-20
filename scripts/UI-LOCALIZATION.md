# Panel localization

The panel defaults to English. The globe button immediately after **Restart core** switches between English and Russian. The browser stores the choice in the `ui_language` cookie; no configuration file or API setting is added.

`vendor/panel/panel/ui_i18n.py` translates static template fragments before values are inserted. `ui_catalog.js` is the shared offline glossary. `ui_i18n.js` handles the button and displayed API messages. API responses and persisted data retain their original representation. Quoted user names, configuration examples and placeholders are preserved.

Use **core**, **main route**, **rule**, **connection**, **subscription**, **load balancing**, and **draft** consistently. Use **kernel** only for the container's Linux kernel.

Checks:

```sh
python -m unittest discover -s tests -p test_ui_i18n.py
python scripts/verify-ui-localization.py
node scripts/verify-ui-browser.cjs
```

The browser check requires Playwright and Chrome. It intercepts requests with local fixtures, opens all sections in both languages, checks script errors and untranslated UI text, compares form values and JSON data (excluding observation timestamps), and verifies a language round trip without POST requests. Pass a directory containing `en` and `ru` page snapshots as the first argument to check captured pages.

The existing full test suite has four route-test failures on the target router that also occur with the original sources. These are separate from the localization checks.
