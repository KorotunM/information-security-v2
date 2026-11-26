import unittest
import tkinter as tk

from tkinter import ttk

from main import Application, DH_TITLE, ADD_TITLE, MULT_TITLE


def button(widget, text):
    for child in widget.winfo_children():
        if isinstance(child, ttk.Button) and child.cget("text") == text:
            return child
        found = button(child, text)
        if found is not None:
            return found
    return None


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(f"Tk недоступен: {error}")
        self.addCleanup(self.root.destroy)
        self.root.withdraw()
        self.application = Application(self.root)
        self.root.report_callback_exception = self.fail_callback

    def fail_callback(self, exception, value, traceback):
        raise value.with_traceback(traceback)

    def test_menu_buttons_and_diffie_hellman(self):
        app = self.application
        self.assertEqual(
            [
                child.cget("text")
                for child in app.home.winfo_children()
                if isinstance(child, ttk.Button)
            ],
            [DH_TITLE, ADD_TITLE, MULT_TITLE],
        )
        button(app.home, DH_TITLE).invoke()
        self.assertIn(DH_TITLE, self.root.title())
        button(app.dh, "Проверить обмен").invoke()
        self.assertIn("Общий секрет — 12", app.dh.status.cget("text"))
        app.dh.fields[3][1].set("8")
        button(app.dh, "Проверить обмен").invoke()
        self.assertIn("Общий секрет — 4", app.dh.status.cget("text"))
        app.dh.fields[0][1].set("21")
        button(app.dh, "Проверить обмен").invoke()
        self.assertIn("простым числом", app.dh.status.cget("text"))
        self.assertEqual(app.dh.values[0][1].cget("text"), "A = g^a mod q")
        button(app.dh, "← К алгоритмам").invoke()
        self.assertEqual(self.root.title(), "Защита информации")

    def test_knapsack_examples_and_separate_operations(self):
        app = self.application
        for page, title, ciphertext in (
            (app.additive, ADD_TITLE, "567 648"),
            (app.multiplicative, MULT_TITLE, "5957337453 8496292532"),
        ):
            with self.subTest(title=title):
                button(app.home, title).invoke()
                self.assertIn(title, self.root.title())
                button(page, "Загрузить пример").invoke()
                self.assertEqual(page.ciphertext.get(), ciphertext)
                self.assertEqual(page.recovered.get(), "hi")
                self.assertEqual(len(page.table.get_children()), 2)

                page.message.set(" a z  ")
                button(page, "Зашифровать").invoke()
                self.assertEqual(page.recovered.get(), "")
                page.ciphertext.set(page.ciphertext.get().replace(" ", ", "))
                button(page, "Расшифровать").invoke()
                self.assertEqual(page.recovered.get(), " a z  ")

                page.ciphertext.set("12,,q")
                button(page, "Расшифровать").invoke()
                self.assertIn("целые числа", page.status.cget("text"))
                self.assertEqual(page.recovered.get(), "")
                self.assertEqual(page.table.get_children(), ())
                button(page, "← К алгоритмам").invoke()
                self.assertEqual(self.root.title(), "Защита информации")

    def test_knapsack_custom_base_in_all_operations(self):
        app = self.application
        for page, weights, modulus, parameter, ciphertext in (
            (app.additive, "2, 5, 16, 50", "149", "31", "158 218"),
            (app.multiplicative, "2, 3, 5", "1009", "5", "934 16"),
        ):
            with self.subTest(title=page.title):
                self.assertEqual(page.base.get(), "14")
                page.base.set("3")
                page.weights.set(weights)
                page.modulus.set(modulus)
                page.parameter.set(parameter)
                button(page, "Зашифровать").invoke()
                self.assertEqual(page.ciphertext.get(), ciphertext)
                button(page, "Расшифровать").invoke()
                self.assertEqual(page.recovered.get(), "hi")
                button(page, "Проверить цикл").invoke()
                self.assertEqual(page.ciphertext.get(), ciphertext)
                self.assertEqual(page.recovered.get(), "hi")

                page.base.set("6")
                self.assertEqual(page.recovered.get(), "")
                self.assertEqual(page.table.get_children(), ())
                button(page, "Загрузить пример").invoke()
                self.assertEqual(page.base.get(), "14")
                self.assertEqual(page.recovered.get(), "hi")

    def test_knapsack_invalid_base_and_incompatible_key(self):
        app = self.application
        for page in (app.additive, app.multiplicative):
            for base, message in (
                ("3.5", "Введите целое число"),
                ("1", "не меньше 2"),
                ("3", "не менее 3 весов"),
                ("1" + "0" * 100, "(p − 1)" if page is app.additive else "p − 1"),
            ):
                with self.subTest(title=page.title, p=base):
                    page.base.set(base)
                    button(page, "Проверить цикл").invoke()
                    self.assertIn(message, page.status.cget("text"))
                    self.assertEqual(page.recovered.get(), "")


if __name__ == "__main__":
    unittest.main()
