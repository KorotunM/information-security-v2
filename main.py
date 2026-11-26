"""Оконное приложение для трёх учебных задач по криптографии."""

import re
import tkinter as tk
from tkinter import ttk

from algorithms import (
    AdditiveKey,
    Block,
    MultiplicativeKey,
    THRESHOLD,
    decrypt,
    diffie_hellman,
    encrypt,
)


BACKGROUND = "#eef2f7"
SURFACE = "#ffffff"
TEXT = "#15243b"
MUTED = "#445875"
BLUE = "#1f4fb5"
SUCCESS = "#176047"
ERROR = "#a22429"
FONT = "Segoe UI"

DH_TITLE = "Диффи — Хеллман"
ADD_TITLE = "Аддитивная рюкзачная криптосистема"
MULT_TITLE = "Мультипликативная рюкзачная криптосистема"
DH_EXAMPLE = ("23", "5", "6", "7")


def configure_styles(root: tk.Tk) -> None:
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BACKGROUND, foreground=TEXT, font=(FONT, 11))
    style.configure("Title.TLabel", font=(FONT, 25, "bold"))
    style.configure("PageTitle.TLabel", font=(FONT, 22, "bold"))
    style.configure("Hint.TLabel", foreground=MUTED)
    style.configure("Card.TFrame", background=SURFACE)
    style.configure("Card.TLabel", background=SURFACE)
    style.configure("Section.TLabel", background=SURFACE, font=(FONT, 12, "bold"))
    style.configure("Result.TLabel", background=SURFACE, font=(FONT, 16, "bold"))
    style.configure("TEntry", padding=(8, 4), fieldbackground=SURFACE)
    style.map("TEntry", fieldbackground=[("readonly", BACKGROUND)])
    style.configure("TButton", padding=(12, 7), background=SURFACE)
    style.configure(
        "Primary.TButton", background=BLUE, foreground="white", bordercolor=BLUE
    )
    style.map(
        "Primary.TButton", background=[("pressed", "#153f95"), ("active", "#2661d3")]
    )
    style.configure(
        "Menu.TButton", font=(FONT, 17, "bold"), padding=(26, 24), anchor="w"
    )
    style.map(
        "Menu.TButton", background=[("pressed", "#d5e2ff"), ("active", "#e4edff")]
    )
    style.configure(
        "Treeview", rowheight=27, background=SURFACE, fieldbackground=SURFACE
    )
    style.configure("Treeview.Heading", font=(FONT, 10, "bold"), background="#dfe7f3")


def integer(value: str, label: str) -> int:
    try:
        return int(value)
    except ValueError as error:
        raise ValueError(f"Введите целое число в поле «{label}».") from error


def integer_list(value: str, label: str) -> list[int]:
    value = value.strip()
    if not value:
        return []
    if value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    try:
        return [int(part) for part in re.split(r"\s*[,;]\s*|\s+", value)]
    except ValueError as error:
        raise ValueError(
            f"В поле «{label}» введите целые числа через пробел или запятую."
        ) from error


def input_field(
    parent,
    label: str,
    value: str,
    row: int,
    column: int,
    *,
    readonly=False,
    columnspan=1,
):
    group = ttk.Frame(parent, style="Card.TFrame")
    group.grid(
        row=row,
        column=column,
        columnspan=columnspan,
        sticky="ew",
        padx=(0, 10),
        pady=(0, 6),
    )
    ttk.Label(group, text=label, style="Card.TLabel").pack(anchor="w", pady=(0, 3))
    variable = tk.StringVar(group, value=value)
    entry = ttk.Entry(group, textvariable=variable, width=12, font=(FONT, 11))
    if readonly:
        entry.state(["readonly"])
    entry.pack(fill="x")
    return variable, entry


class Application:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.geometry("1000x790")
        root.minsize(790, 710)
        root.configure(background=BACKGROUND)
        configure_styles(root)
        container = ttk.Frame(root, padding=(30, 15))
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        self.home = ttk.Frame(container, padding=(16, 34))
        self.dh = DiffieHellmanPage(container, self.show_home)
        self.additive = KnapsackPage(container, self.show_home, AdditiveKey)
        self.multiplicative = KnapsackPage(container, self.show_home, MultiplicativeKey)
        for page in (self.home, self.dh, self.additive, self.multiplicative):
            page.grid(row=0, column=0, sticky="nsew")

        ttk.Label(
            self.home, text="Криптографические алгоритмы", style="Title.TLabel"
        ).pack(anchor="w", pady=(0, 24))
        for page in (self.dh, self.additive, self.multiplicative):
            button = ttk.Button(
                self.home,
                text=page.title,
                style="Menu.TButton",
                command=lambda selected=page: self.show(selected),
            )
            button.pack(fill="x", pady=(0, 12))

        self.show_home()
        root.bind("<Escape>", lambda event: self.show_home())

    def show(self, page):
        self.root.title(f"{page.title} · Защита информации")
        page.tkraise()
        page.first_input.focus_set()

    def show_home(self):
        self.root.title("Защита информации")
        self.home.tkraise()
        self.home.focus_set()


class AlgorithmPage(ttk.Frame):
    def __init__(self, parent, go_home, title: str):
        super().__init__(parent)
        self.title = title
        navigation = ttk.Frame(self)
        navigation.pack(fill="x")
        ttk.Button(navigation, text="← К алгоритмам", command=go_home).pack(side="left")
        ttk.Button(navigation, text="Загрузить пример", command=self.load_example).pack(
            side="right"
        )
        ttk.Label(self, text=title, style="PageTitle.TLabel", wraplength=710).pack(
            anchor="w", pady=(10, 10)
        )

    def card(self, *, expand=False):
        card = ttk.Frame(self, style="Card.TFrame", padding=(16, 10))
        card.pack(fill="both" if expand else "x", expand=expand, pady=(0, 7))
        return card

    def status_line(self):
        return ttk.Label(
            self, style="Hint.TLabel", text=" ", wraplength=710, justify="left"
        )


class DiffieHellmanPage(AlgorithmPage):
    def __init__(self, parent, go_home):
        super().__init__(parent, go_home, DH_TITLE)
        form = self.card()
        ttk.Label(form, text="Параметры обмена", style="Section.TLabel").grid(
            row=0, columnspan=4, sticky="w", pady=(0, 7)
        )
        self.fields = []
        for column, (label, value) in enumerate(
            zip(
                ("Модуль q", "Генератор g", "Участник A · a", "Участник B · b"),
                DH_EXAMPLE,
            )
        ):
            form.columnconfigure(column, weight=1, uniform="dh")
            field, entry = input_field(form, label, value, 1, column)
            if column == 0:
                self.first_input = entry
            self.fields.append((label, field))
            entry.bind("<Return>", lambda event: self.calculate())
        ttk.Button(
            form,
            text="Проверить обмен",
            style="Primary.TButton",
            command=self.calculate,
        ).grid(row=2, columnspan=4, sticky="w", pady=(3, 1))

        result = self.card()
        for column, name in enumerate(("Участник A", "Участник B")):
            result.columnconfigure(column, weight=1, uniform="participants")
            ttk.Label(result, text=name, style="Section.TLabel").grid(
                row=0, column=column, sticky="w"
            )

        self.values = []
        for row, (caption, formula) in enumerate(
            (
                ("Открытое значение A · A → B", "A = g^a mod q"),
                ("Открытое значение B · B → A", "B = g^b mod q"),
                ("Секрет по полученному B", "K_A = B^a mod q"),
                ("Секрет по полученному A", "K_B = A^b mod q"),
            )
        ):
            column = row % 2
            label_row = 1 + 2 * (row // 2)
            ttk.Label(result, text=caption, style="Card.TLabel").grid(
                row=label_row, column=column, sticky="w", pady=(10, 0)
            )
            output = ttk.Label(
                result, text=formula, style="Result.TLabel", wraplength=320
            )
            output.grid(row=label_row + 1, column=column, sticky="w", pady=(0, 8))
            self.values.append((formula, output))

        self.status = self.status_line()
        self.status.pack(anchor="w", pady=(4, 0))
        for _, variable in self.fields:
            variable.trace_add("write", lambda *_: self.clear_result())

    def clear_result(self):
        self.status.configure(text=" ")
        for formula, output in self.values:
            output.configure(text=formula)

    def load_example(self):
        for (_, variable), value in zip(self.fields, DH_EXAMPLE):
            variable.set(value)
        self.calculate()

    def calculate(self):
        self.clear_result()
        try:
            q, g, a, b = [
                integer(variable.get(), label) for label, variable in self.fields
            ]
            exchange = diffie_hellman(q, g, a, b)
        except ValueError as error:
            self.status.configure(text=str(error), foreground=ERROR)
            return

        results = (
            f"A = {g}^{a} mod {q} = {exchange.alice_public}",
            f"B = {g}^{b} mod {q} = {exchange.bob_public}",
            f"K_A = {exchange.bob_public}^{a} mod {q} = {exchange.alice_secret}",
            f"K_B = {exchange.alice_public}^{b} mod {q} = {exchange.bob_secret}",
        )
        for (_, output), formula in zip(self.values, results):
            output.configure(text=formula)
        if exchange.matches:
            self.status.configure(
                text=f"Секреты совпали. Общий секрет — {exchange.alice_secret}.",
                foreground=SUCCESS,
            )
        else:
            self.status.configure(text="Секреты не совпали.", foreground=ERROR)


class KnapsackPage(AlgorithmPage):
    def __init__(
        self, parent, go_home, key_type: type[AdditiveKey] | type[MultiplicativeKey]
    ):
        self.key_type = key_type
        additive = key_type is AdditiveKey
        self.example = (
            ("2, 29", "409", "31") if additive else ("2, 3", "13060694051", "11")
        )
        self.parameter_label = "Множитель a" if additive else "Показатель s"
        title = ADD_TITLE if additive else MULT_TITLE
        super().__init__(parent, go_home, title)

        keys = self.card()
        for column in range(4):
            keys.columnconfigure(column, weight=1, uniform="keys")
        ttk.Label(keys, text="Параметры ключа", style="Section.TLabel").grid(
            row=0, columnspan=4, sticky="w", pady=(0, 5)
        )
        self.base, self.first_input = input_field(
            keys, "Основание p", str(THRESHOLD), 1, 0
        )
        self.weights, _ = input_field(keys, "Закрытые веса W", self.example[0], 1, 1)
        self.modulus, _ = input_field(keys, "Модуль m", self.example[1], 1, 2)
        self.parameter, _ = input_field(
            keys, self.parameter_label, self.example[2], 1, 3
        )
        public_label = "Открытый рюкзак B" if additive else "Открытый ключ B и m"
        key_output = ttk.Frame(keys, style="Card.TFrame")
        key_output.grid(row=2, columnspan=4, sticky="ew", padx=(0, 10))
        ttk.Label(key_output, text=public_label, style="Card.TLabel").pack(
            side="left", padx=(0, 8)
        )
        self.public_key = tk.StringVar(key_output)
        ttk.Entry(
            key_output, textvariable=self.public_key, state="readonly", font=(FONT, 11)
        ).pack(side="left", fill="x", expand=True)

        work = self.card()
        for column in range(2):
            work.columnconfigure(column, weight=1, uniform="message")
        self.message, message_input = input_field(
            work, "Отправитель · исходное сообщение", "hi", 0, 0
        )
        self.recovered, _ = input_field(
            work, "Получатель · расшифрованное сообщение", "", 0, 1, readonly=True
        )
        self.ciphertext, cipher_input = input_field(
            work, "Шифртекст через пробел или запятую", "", 1, 0, columnspan=2
        )
        actions = ttk.Frame(work, style="Card.TFrame")
        actions.grid(row=2, columnspan=2, sticky="w", pady=(0, 2))
        ttk.Button(actions, text="Зашифровать", command=self.encrypt_message).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(actions, text="Расшифровать", command=self.decrypt_message).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(
            actions,
            text="Проверить цикл",
            style="Primary.TButton",
            command=self.check_cycle,
        ).pack(side="left")
        message_input.bind("<Return>", lambda event: self.encrypt_message())
        cipher_input.bind("<Return>", lambda event: self.decrypt_message())

        self.status = self.status_line()
        self.status.pack(side="bottom", anchor="w", pady=(1, 0))
        detail = self.card(expand=True)
        detail.columnconfigure(0, weight=1)
        detail.rowconfigure(1, weight=1)
        ttk.Label(detail, text="Расчёт по символам", style="Section.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 5)
        )
        headers = (
            ("№", 42),
            ("Символ", 75),
            ("Код", 55),
            ("Цифры блока", 125),
            ("Шифртекст c", 135),
            ("Закрытая сумма c′" if additive else "Закрытое произведение u", 186),
        )
        self.table = ttk.Treeview(
            detail, columns=tuple(range(len(headers))), show="headings", height=3
        )
        for index, (label, width) in enumerate(headers):
            self.table.heading(index, text=label)
            self.table.column(
                index, width=width, minwidth=width, anchor="center", stretch=index >= 3
            )
        self.table.grid(row=1, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(detail, orient="vertical", command=self.table.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(
            detail, orient="horizontal", command=self.table.xview
        )
        horizontal.grid(row=2, column=0, sticky="ew")
        self.table.configure(
            yscrollcommand=scrollbar.set, xscrollcommand=horizontal.set
        )

        for variable in (
            self.message,
            self.ciphertext,
            self.base,
            self.weights,
            self.modulus,
            self.parameter,
        ):
            variable.trace_add("write", lambda *_: self.clear_result())

    def clear_result(self):
        self.status.configure(text=" ")
        self.public_key.set("")
        self.recovered.set("")
        self.table.delete(*self.table.get_children())

    def load_example(self):
        self.base.set(str(THRESHOLD))
        for variable, value in zip(
            (self.weights, self.modulus, self.parameter), self.example
        ):
            variable.set(value)
        self.message.set("hi")
        self.check_cycle()

    def read_key(self) -> AdditiveKey | MultiplicativeKey:
        base = integer(self.base.get(), "Основание p")
        weights = tuple(integer_list(self.weights.get(), "Закрытые веса W"))
        modulus = integer(self.modulus.get(), "Модуль m")
        parameter = integer(self.parameter.get(), self.parameter_label)
        return self.key_type(weights, modulus, parameter, base=base)

    def display(self, key: AdditiveKey | MultiplicativeKey, blocks: list[Block]):
        public = str(key.public_weights)
        if isinstance(key, MultiplicativeKey):
            public = f"B = {public}   m = {key.modulus}"
        self.public_key.set(public)
        for index, block in enumerate(blocks, start=1):
            self.table.insert(
                "",
                "end",
                values=(
                    index,
                    "пробел" if block.symbol == " " else block.symbol,
                    block.code,
                    " ".join(map(str, block.digits)),
                    block.ciphertext,
                    "—" if block.private_value is None else block.private_value,
                ),
            )

    def encrypt_message(self):
        self.clear_result()
        try:
            key = self.read_key()
            blocks = encrypt(self.message.get(), key)
        except ValueError as error:
            self.status.configure(text=str(error), foreground=ERROR)
            return
        self.ciphertext.set(" ".join(str(block.ciphertext) for block in blocks))
        self.display(key, blocks)
        self.status.configure(
            text=f"Зашифровано символов — {len(blocks)}.", foreground=SUCCESS
        )

    def decrypt_message(self):
        self.clear_result()
        try:
            key = self.read_key()
            ciphertext = integer_list(self.ciphertext.get(), "Шифртекст")
            blocks = decrypt(ciphertext, key)
        except ValueError as error:
            self.status.configure(text=str(error), foreground=ERROR)
            return
        self.recovered.set("".join(block.symbol for block in blocks))
        self.display(key, blocks)
        self.status.configure(
            text=f"Расшифровано блоков — {len(blocks)}.", foreground=SUCCESS
        )

    def check_cycle(self):
        self.clear_result()
        try:
            key = self.read_key()
            message = self.message.get()
            ciphertext = [block.ciphertext for block in encrypt(message, key)]
            blocks = decrypt(ciphertext, key)
        except ValueError as error:
            self.status.configure(text=str(error), foreground=ERROR)
            return
        self.ciphertext.set(" ".join(map(str, ciphertext)))
        recovered = "".join(block.symbol for block in blocks)
        self.recovered.set(recovered)
        self.display(key, blocks)
        if message == recovered:
            self.status.configure(
                text=f"Сообщение восстановлено без изменений. Символов — {len(blocks)}.",
                foreground=SUCCESS,
            )
        else:
            self.status.configure(
                text="Восстановленное сообщение не совпало с исходным.",
                foreground=ERROR,
            )


if __name__ == "__main__":
    window = tk.Tk()
    Application(window)
    window.mainloop()
