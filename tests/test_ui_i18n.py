import io
import json
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vendor/panel/panel'))
import ui_i18n as ui
import manage_ru_blocked as app
import routing_panel


class LocalizationTests(unittest.TestCase):
    def setUp(self):
        self.language = ui.LANGUAGE.set('en')
        self.addCleanup(ui.LANGUAGE.reset, self.language)

    def test_placeholder_values_and_markup_are_preserved(self):
        template = '<button data-value="{value}">Перезапустить ядро</button>'
        self.assertEqual(ui.text(template), '<button data-value="{value}">Restart core</button>')
        value = 'Включено <script>data.message</script>'
        self.assertEqual(ui.text('Название: {name}').format(name=value), 'Name: ' + value)
        self.assertEqual(ui.text('ЗАПОЛНИТЕ-'), 'ЗАПОЛНИТЕ-')
        self.assertEqual(ui.message('Прокси «Включено»'), 'Proxy «Включено»')

    def test_russian_templates_are_byte_for_byte_unchanged(self):
        ui.select_language('ui_language=ru')
        value = '<label title="Основной маршрут">Название {name}</label>'
        self.assertEqual(ui.text(value), value)

    def test_invalid_cookie_and_parallel_requests(self):
        ui.select_language('ui_language=invalid')
        self.assertEqual(ui.LANGUAGE.get(), 'en')
        values = []
        def russian():
            ui.select_language('ui_language=ru')
            values.append(ui.text('Правила'))
        thread = threading.Thread(target=russian)
        thread.start()
        thread.join()
        self.assertEqual(values, ['Правила'])
        self.assertEqual(ui.text('Правила'), 'Rules')

    def test_script_translation_preserves_serialized_user_data(self):
        source = 'const seed={"name":"Включено data.message"};const text=data.message;'
        result = ui.localize_script(source)
        self.assertIn('"Включено data.message"', result)
        self.assertIn('const text=window.uiText(data.message)', result)
        page = '<script type="application/json">{"message":"Включено"}</script>'
        self.assertEqual(ui.localize_page_scripts(page), page)

    def test_api_is_unchanged_even_with_english_cookie(self):
        handler = object.__new__(app.Handler)
        handler.path = '/api/actions/history?before=not-an-integer'
        handler.headers = {'Cookie': 'ui_language=en'}
        handler.wfile = io.BytesIO()
        status = []
        handler.send_response = status.append
        handler.send_header = lambda *args: None
        handler.end_headers = lambda: None
        handler.do_GET()
        self.assertEqual(status, [400])
        self.assertEqual(json.loads(handler.wfile.getvalue()), {'message': 'Некорректный номер действия'})

    def test_language_button_does_not_submit_any_form(self):
        for language in ('en', 'ru'):
            ui.select_language('ui_language=' + language)
            with patch.object(routing_panel, 'global_info', return_value={'all': ['DIRECT'], 'now': 'DIRECT'}), patch.object(routing_panel, 'read_settings', return_value={'main_proxy': 'DIRECT', 'services_enabled': True}):
                page = routing_panel.render_routing_panel()
            self.assertLess(page.index('form="core-restart-form"'), page.index('id="ui-language-toggle"'))
            self.assertIn('<button type="button" id="ui-language-toggle"', page)
            self.assertIn('value="core_restart"', page)


if __name__ == '__main__':
    unittest.main()
