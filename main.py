import ast
import base64
import tkinter
import zlib

import Crypto
import customtkinter
import elgamal.elgamal
from Crypto.Signature import PKCS1_PSS, DSS
from elgamal.elgamal import Elgamal

from Crypto.Cipher import CAST, AES, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256, SHAKE128

import keys_gen
import keys_io
import pgp_message
from Crypto.Util.Padding import pad, unpad
from PIL import Image

customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("green")


class PGP_App(customtkinter.CTk):
    def load_frame_welcome(self, old_frame: customtkinter.CTkFrame):
        self.loaded_frame = "start"
        if old_frame:
            old_frame.destroy()
        img = customtkinter.CTkImage(dark_image=Image.open("./Img/Dark/" + self.current_image),
                                     light_image=Image.open("./Img/Light/" + self.current_image),
                                     size=(1400, 780))
        frame = customtkinter.CTkFrame(master=self)

        frame.pack(pady=40, padx=30, fill="both", expand=True)

        label_welcome = customtkinter.CTkLabel(master=frame, image=img, text="", font=("Roboto", 26), corner_radius=12)
        label_welcome.place(x=0, y=0)
        button_next = customtkinter.CTkButton(master=frame, text="Start", font=("Roboto Bold", 22), corner_radius=12,
                                              command=lambda: self.transition("12"), width=320, height=40)
        button_next.place(x=80, y=600)

        return frame

    def load_frame_keys(self, old_frame: customtkinter.CTkFrame):
        self.loaded_frame = "keys"
        if old_frame:
            old_frame.destroy()

        # Frame init
        frame = customtkinter.CTkFrame(master=self)
        frame.grid_columnconfigure(0, weight=0)
        frame.grid_columnconfigure(1, weight=0)
        frame.grid_columnconfigure(2, weight=4)
        frame.grid_rowconfigure((0, 1, 2), weight=0)
        frame.grid_rowconfigure(3, weight=1)
        frame.pack(expand=True, fill="both")

        # Sidebar
        frame_sidebar = customtkinter.CTkFrame(master=frame, width=140, corner_radius=0)
        frame_sidebar.grid(row=0, column=0, rowspan=4, sticky="news")
        frame_sidebar.grid_rowconfigure(6, weight=1)
        label_main = customtkinter.CTkLabel(master=frame_sidebar, text="PGP ZP Project", font=("Roboto Bold", 20))
        label_main.grid(row=0, column=0, padx=20, pady=(20, 10), stick="news")
        button_keys_menu = customtkinter.CTkButton(master=frame_sidebar, text="Keys Menu", font=("Roboto", 14),
                                                   state="disabled")
        button_keys_menu.grid(row=1, column=0, padx=20, pady=(30, 10), stick="news")
        button_send_menu = customtkinter.CTkButton(master=frame_sidebar, text="Send Message", font=("Roboto", 14),
                                                   command=lambda: self.transition("23"))
        button_send_menu.grid(row=2, column=0, padx=20, pady=10, stick="news")
        button_receive_menu = customtkinter.CTkButton(master=frame_sidebar, text="Receive Message", font=("Roboto", 14),
                                                      command=lambda: self.transition("24"))

        button_receive_menu.grid(row=3, column=0, padx=20, pady=10, stick="news")

        appearance_frame = customtkinter.CTkFrame(master=frame_sidebar)
        appearance_frame.grid(row=4, rowspan=2, column=0, padx=20, pady=(180, 20), stick="sew")
        customtkinter.CTkLabel(master=appearance_frame, text="Change Appearance", font=("Roboto", 14)).grid(row=0,
                                                                                                            column=0,
                                                                                                            padx=10,
                                                                                                            pady=(
                                                                                                                10, 0),
                                                                                                            stick="new")
        self.color_option_var = customtkinter.StringVar(0)
        self.color_option_var.set("Switch Color")
        self.color_option = customtkinter.CTkOptionMenu(master=appearance_frame, values=["Green", "Blue", "Dark Blue"],
                                                        command=self.choose_color, font=("Roboto", 14),
                                                        variable=self.color_option_var,
                                                        dropdown_font=("Roboto", 12))
        self.color_option.grid(row=1, column=0, padx=10, pady=(10, 0), stick="news")
        button_switch = customtkinter.CTkButton(master=appearance_frame, text="Switch Mode", font=("Roboto", 14),
                                                command=self.switch_appearance)
        button_switch.grid(row=2, column=0, pady=(10, 10), padx=10, stick="sew")
        button_back = customtkinter.CTkButton(master=frame_sidebar, text="Start Menu", font=("Roboto", 14),
                                              command=lambda: self.transition("21"))
        button_back.grid(row=6, column=0, padx=20, pady=(20, 40), stick="sew")

        # Create Keys
        frame_create_keys = customtkinter.CTkFrame(master=frame)
        frame_create_keys.grid(row=0, column=1, rowspan=3, sticky="news", pady=20, padx=20)
        frame_create_keys.grid_columnconfigure((0, 1), weight=1)
        frame_create_keys.grid_rowconfigure(7, weight=1)

        frame_create_keys_label1 = customtkinter.CTkLabel(master=frame_create_keys, text="Create new key pair",
                                                          font=("Roboto", 20))
        frame_create_keys_label1.grid(row=0, column=0, columnspan=2, sticky="news", pady=20)
        self.frame_create_keys_username = customtkinter.CTkEntry(master=frame_create_keys, placeholder_text="Username")
        self.frame_create_keys_username.grid(row=1, column=0, columnspan=2, sticky="news", pady=20, padx=20)
        self.frame_create_keys_mail = customtkinter.CTkEntry(master=frame_create_keys, placeholder_text="E-Mail")
        self.frame_create_keys_mail.grid(row=2, column=0, columnspan=2, sticky="news", pady=(0, 20), padx=20)
        frame_create_keys_label2 = customtkinter.CTkLabel(master=frame_create_keys,
                                                          text="Choose Encryption/Signature algorythm",
                                                          font=("Roboto", 14))
        frame_create_keys_label2.grid(row=3, column=0, columnspan=2, sticky="news", pady=20)
        self.alg_radio = customtkinter.IntVar(0)
        frame_create_keys_alg_radio1 = customtkinter.CTkRadioButton(master=frame_create_keys,
                                                                    text="RSA Encryption & Signature",
                                                                    variable=self.alg_radio, value=1)
        frame_create_keys_alg_radio1.grid(row=4, column=0, pady=(0, 20), padx=(20, 10))
        frame_create_keys_alg_radio2 = customtkinter.CTkRadioButton(master=frame_create_keys,
                                                                    text="ElGamal & DSA", variable=self.alg_radio,
                                                                    value=2)
        frame_create_keys_alg_radio2.grid(row=4, column=1, pady=(0, 20), padx=(10, 20))

        frame_create_keys_label3 = customtkinter.CTkLabel(master=frame_create_keys,
                                                          text="Choose key length",
                                                          font=("Roboto", 14))
        frame_create_keys_label3.grid(row=5, column=0, columnspan=2, sticky="news", pady=10)
        self.key_radio = customtkinter.IntVar(0)
        frame_create_keys_key_radio1 = customtkinter.CTkRadioButton(master=frame_create_keys,
                                                                    text="1024",
                                                                    variable=self.key_radio, value=1024)
        frame_create_keys_key_radio1.grid(row=6, column=0, pady=(0, 20))
        frame_create_keys_key_radio2 = customtkinter.CTkRadioButton(master=frame_create_keys,
                                                                    text="2048", variable=self.key_radio, value=2048)
        frame_create_keys_key_radio2.grid(row=6, column=1, pady=(0, 20))

        frame_button_create_keys = customtkinter.CTkButton(master=frame_create_keys, text="Create", font=("Roboto", 14),
                                                           command=self.enter_password)
        frame_button_create_keys.grid(row=7, column=0, columnspan=2, padx=20, stick="new", pady=20)

        # Delete Key Pairs

        frame_delete_keys = customtkinter.CTkFrame(master=frame)
        frame_delete_keys.grid(row=3, column=1, sticky="news", pady=(0, 20), padx=20)
        frame_delete_keys.grid_columnconfigure((0, 1), weight=1)
        frame_delete_keys.grid_rowconfigure(1, weight=1)

        frame_delete_keys_label1 = customtkinter.CTkLabel(master=frame_delete_keys, text="Delete key pair",
                                                          font=("Roboto", 20))
        frame_delete_keys_label1.grid(row=0, column=0, columnspan=2, sticky="news", pady=20)
        frame_delete_keys_scroll = customtkinter.CTkScrollableFrame(master=frame_delete_keys,
                                                                    label_text="Public key ID - Encripted private key",
                                                                    label_anchor="w")
        frame_delete_keys_scroll.grid(row=1, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 10))
        frame_delete_keys_scroll.grid_columnconfigure(0, weight=1)
        self.delete_key_var = customtkinter.IntVar(0)
        i = 0
        for key, value in keys_gen.dict_private_key_ring.items():
            text = "PuK:        " + key[1] + "\n" + "E(PrK):    " + value[1][0:28] + "..."
            customtkinter.CTkRadioButton(master=frame_delete_keys_scroll,
                                         variable=self.delete_key_var, text=text, value=int(key[1]),
                                         border_width_checked=4,
                                         border_width_unchecked=2,
                                         command=lambda: frame_button_delete_keys.configure(state="normal")).grid(row=i,
                                                                                                                  column=0,
                                                                                                                  stick="w",
                                                                                                                  pady=5)
            i = i + 1
        frame_button_delete_keys = customtkinter.CTkButton(master=frame_delete_keys, text="Delete key pair",
                                                           state="disabled",
                                                           font=("Roboto", 14), command=self.delete_key)
        frame_button_delete_keys.grid(row=2, column=0, columnspan=2, padx=20, stick="sew", pady=20)

        # Public keys
        frame_public_keys = customtkinter.CTkFrame(master=frame)
        frame_public_keys.grid(row=0, column=2, rowspan=6, sticky="news", pady=20, padx=(0, 20))
        frame_public_keys.grid_columnconfigure((0, 1), weight=1)
        frame_public_keys.grid_rowconfigure(6, weight=1)
        frame_public_keys_label1 = customtkinter.CTkLabel(master=frame_public_keys, text="Public keys",
                                                          font=("Roboto", 20))
        frame_public_keys_label1.grid(row=0, column=0, columnspan=2, sticky="news", pady=(20, 14))

        frame_public_keys_table = customtkinter.CTkFrame(master=frame_public_keys)
        frame_public_keys_table.grid(row=1, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 5))
        frame_public_keys_scroll = customtkinter.CTkScrollableFrame(master=frame_public_keys)
        frame_public_keys_scroll.grid(row=2, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 40))
        frame_public_keys_table.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="a")
        frame_public_keys_scroll.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="a")
        customtkinter.CTkLabel(master=frame_public_keys_table, text="User ID").grid(row=0, column=0, padx=(10, 0))
        customtkinter.CTkLabel(master=frame_public_keys_table, text="Key ID").grid(row=0, column=1, columnspan=2)
        customtkinter.CTkLabel(master=frame_public_keys_table, text="PuK").grid(row=0, column=3, columnspan=2)
        customtkinter.CTkLabel(master=frame_public_keys_table, text="E-Mail").grid(row=0, column=5, columnspan=2,
                                                                                   padx=(0, 4))
        customtkinter.CTkLabel(master=frame_public_keys_table, text="Algorithm").grid(row=0, column=7, padx=(0, 24))
        customtkinter.CTkLabel(master=frame_public_keys_table, text="Time").grid(row=0, column=8, padx=(0, 30))
        self.public_key_var = customtkinter.IntVar(0)
        i = 0
        for key, value in keys_gen.dict_public_key_ring.items():
            public_key_val = value[0]
            if len(public_key_val) > 40:
                public_key_val = public_key_val[0:40] + "..."
            customtkinter.CTkRadioButton(master=frame_public_keys_scroll, text=key[0], border_width_unchecked=1,
                                         border_width_checked=5,
                                         variable=self.public_key_var, value=int(key[1]),
                                         command=lambda: self.enable_button(self.frame_private_keys_button2)).grid(
                row=i,
                column=0,
                padx=(
                    16,
                    0))
            customtkinter.CTkLabel(master=frame_public_keys_scroll, text=key[1]).grid(row=i, column=1, columnspan=2)
            customtkinter.CTkLabel(master=frame_public_keys_scroll, text=public_key_val, wraplength=160).grid(row=i,
                                                                                                              column=3,
                                                                                                              columnspan=2,
                                                                                                              pady=(
                                                                                                                  0, 5))
            customtkinter.CTkLabel(master=frame_public_keys_scroll, text=value[1], wraplength=160).grid(row=i, column=5,
                                                                                                        columnspan=2)
            customtkinter.CTkLabel(master=frame_public_keys_scroll, text=value[2]).grid(row=i, column=7)
            customtkinter.CTkLabel(master=frame_public_keys_scroll, text=value[3], wraplength=100).grid(row=i, column=8)
            i = i + 1

        # Private Keys
        frame_private_keys_label1 = customtkinter.CTkLabel(master=frame_public_keys, text="Private keys",
                                                           font=("Roboto", 20))
        frame_private_keys_label1.grid(row=3, column=0, columnspan=2, sticky="news", pady=(20, 14))

        frame_private_keys_table = customtkinter.CTkFrame(master=frame_public_keys)
        frame_private_keys_table.grid(row=4, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 5))
        frame_private_keys_scroll = customtkinter.CTkScrollableFrame(master=frame_public_keys)
        frame_private_keys_scroll.grid(row=5, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 20))
        frame_private_keys_table.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="p")
        frame_private_keys_scroll.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="p")
        customtkinter.CTkLabel(master=frame_private_keys_table, text="User ID").grid(row=0, column=0, padx=(10, 0))
        customtkinter.CTkLabel(master=frame_private_keys_table, text="Key ID").grid(row=0, column=1, columnspan=2)
        customtkinter.CTkLabel(master=frame_private_keys_table, text="PuK").grid(row=0, column=3, columnspan=2)
        customtkinter.CTkLabel(master=frame_private_keys_table, text="E(PrK)").grid(row=0, column=5, columnspan=2,
                                                                                    padx=(0, 4))
        customtkinter.CTkLabel(master=frame_private_keys_table, text="Algorithm").grid(row=0, column=7, padx=(0, 24))
        customtkinter.CTkLabel(master=frame_private_keys_table, text="Time").grid(row=0, column=8, padx=(0, 30))
        self.private_key_var = customtkinter.IntVar(0)
        i = 0
        for key, value in keys_gen.dict_private_key_ring.items():
            public_key_val = value[0]
            if len(public_key_val) > 40:
                public_key_val = public_key_val[0:40] + "..."
            private_key_val = value[1]
            if len(private_key_val) > 40:
                private_key_val = private_key_val[0:40] + "..."
            customtkinter.CTkRadioButton(master=frame_private_keys_scroll, text=key[0], border_width_unchecked=1,
                                         border_width_checked=5,
                                         variable=self.private_key_var, value=int(key[1]),
                                         command=lambda: self.enable_button(self.frame_private_keys_button2)).grid(
                row=i,
                column=0,
                padx=(
                    16,
                    0))
            customtkinter.CTkLabel(master=frame_private_keys_scroll, text=key[1]).grid(row=i, column=1, columnspan=2)
            customtkinter.CTkLabel(master=frame_private_keys_scroll, text=public_key_val, wraplength=160).grid(row=i,
                                                                                                               column=3,
                                                                                                               columnspan=2,
                                                                                                               pady=(
                                                                                                                   0,
                                                                                                                   5))
            customtkinter.CTkLabel(master=frame_private_keys_scroll, text=private_key_val, wraplength=160).grid(row=i,
                                                                                                                column=5,
                                                                                                                columnspan=2)
            customtkinter.CTkLabel(master=frame_private_keys_scroll, text=value[2]).grid(row=i, column=7)
            customtkinter.CTkLabel(master=frame_private_keys_scroll, text=value[3], wraplength=100).grid(row=i,
                                                                                                         column=8)
            i = i + 1

        frame_private_keys_button1 = customtkinter.CTkButton(master=frame_public_keys, text="Import key",
                                                             font=("Roboto", 14),
                                                             command=lambda: self.import_key())
        frame_private_keys_button1.grid(row=6, column=0, stick="ews", padx=(20, 10), pady=(0, 20))
        self.frame_private_keys_button2 = customtkinter.CTkButton(master=frame_public_keys, text="Export key",
                                                                  font=("Roboto", 14), state="disabled",
                                                                  command=lambda: self.export())
        self.frame_private_keys_button2.grid(row=6, column=1, stick="ews", padx=(10, 20), pady=(0, 20))

        return frame

    def load_frame_receive(self, old_frame: customtkinter.CTkFrame):
        self.loaded_frame = "receive"
        if old_frame:
            old_frame.destroy()

        frame = customtkinter.CTkFrame(master=self)
        frame.grid_columnconfigure(0, weight=0)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=3)
        frame.grid_rowconfigure((0, 1, 2, 3), weight=1)
        frame.pack(expand=True, fill="both")
        # sidebar

        frame_sidebar = customtkinter.CTkFrame(master=frame, width=140, corner_radius=0)
        frame_sidebar.grid(row=0, column=0, rowspan=4, sticky="news")
        frame_sidebar.grid_rowconfigure(6, weight=1)
        label_main = customtkinter.CTkLabel(master=frame_sidebar, text="PGP ZP Project", font=("Roboto Bold", 20))
        label_main.grid(row=0, column=0, padx=20, pady=(20, 10), stick="news")
        button_keys_menu = customtkinter.CTkButton(master=frame_sidebar, text="Keys Menu", font=("Roboto", 14),
                                                   command=lambda: self.transition("42"))
        button_keys_menu.grid(row=1, column=0, padx=20, pady=(30, 10), stick="news")
        button_send_menu = customtkinter.CTkButton(master=frame_sidebar, text="Send Message", font=("Roboto", 14),
                                                   command=lambda: self.transition("43"))
        button_send_menu.grid(row=2, column=0, padx=20, pady=10, stick="news")
        button_receive_menu = customtkinter.CTkButton(master=frame_sidebar, text="Receive Message", font=("Roboto", 14),
                                                      state="disabled")
        button_receive_menu.grid(row=3, column=0, padx=20, pady=10, stick="news")

        appearance_frame = customtkinter.CTkFrame(master=frame_sidebar)
        appearance_frame.grid(row=4, rowspan=2, column=0, padx=20, pady=(180, 20), stick="sew")
        customtkinter.CTkLabel(master=appearance_frame, text="Change Appearance", font=("Roboto", 14)).grid(row=0,
                                                                                                            column=0,
                                                                                                            padx=10,
                                                                                                            pady=(
                                                                                                                10, 0),
                                                                                                            stick="new")
        self.color_option_var = customtkinter.StringVar(0)
        self.color_option_var.set("Switch Color")
        self.color_option = customtkinter.CTkOptionMenu(master=appearance_frame, values=["Green", "Blue", "Dark Blue"],
                                                        command=self.choose_color, font=("Roboto", 14),
                                                        variable=self.color_option_var,
                                                        dropdown_font=("Roboto", 12))
        self.color_option.grid(row=1, column=0, padx=10, pady=(10, 0), stick="news")
        button_switch = customtkinter.CTkButton(master=appearance_frame, text="Switch Mode", font=("Roboto", 14),
                                                command=self.switch_appearance)
        button_switch.grid(row=2, column=0, pady=(10, 10), padx=10, stick="sew")
        button_back = customtkinter.CTkButton(master=frame_sidebar, text="Start Menu", font=("Roboto", 14),
                                              command=lambda: self.transition("31"))
        button_back.grid(row=6, column=0, padx=20, pady=(20, 40), stick="sew")

        # frame receive
        frame_receive_message = customtkinter.CTkFrame(master=frame)
        frame_receive_message.grid(row=0, column=1, rowspan=11, sticky="news", pady=20, padx=20)
        frame_receive_message.grid_columnconfigure(0, weight=1)
        frame_receive_message.grid_rowconfigure(8, weight=1)

        # Create the small note-like box
        customtkinter.CTkLabel(frame_receive_message, text="Receive Message", font=("Roboto", 20)).grid(row=0, column=0,
                                                                                                        stick="news",
                                                                                                        padx=20,
                                                                                                        pady=(20, 0))

        self.frame_receive_textarea = customtkinter.CTkTextbox(master=frame_receive_message, wrap="word",
                                                               state="disabled")
        self.frame_receive_textarea.grid(row=1, column=0, stick="news", padx=20, pady=(20, 0))

        btn_dec_ver = customtkinter.CTkButton(master=frame_receive_message, text="Select and Receive Message", font=("Roboto", 14),
                                              command=lambda: self.select_file())
        btn_dec_ver.grid(row=2, column=0, stick="news", padx=20, pady=20)

        self.small_box = customtkinter.CTkLabel(frame_receive_message, text="")
        self.small_box.grid(row=4, column=0, stick="news", padx=20, pady=(20, 0))

        self.btn_save_message = customtkinter.CTkButton(master=frame_receive_message, text="Save Message", font=("Roboto", 14),
                                                   command=self.save_message, state="disabled")
        self.btn_save_message.grid(row=8, column=0, stick="ews", padx=20, pady=20)

        self.user_id = customtkinter.CTkLabel(frame_receive_message, text="")
        self.user_id.grid(row=5, column=0, stick="news", padx=20)

        self.mail = customtkinter.CTkLabel(frame_receive_message, text="")
        self.mail.grid(row=6, column=0,stick="news", padx=20)

        self.sig_time = customtkinter.CTkLabel(frame_receive_message, text="")
        self.sig_time.grid(row=7, column=0, stick="news", padx=20)

        self.verification_ok = customtkinter.CTkLabel(frame_receive_message, text="", font=("Roboto", 16))
        self.verification_ok.grid(row=3, column=0, stick="news", padx=20, pady=10)

        #Public Keys
        frame_public_keys = customtkinter.CTkFrame(master=frame)
        frame_public_keys.grid(row=0, column=2, rowspan=7, sticky="news", pady=20, padx=(0, 20))
        frame_public_keys.grid_columnconfigure((0, 1), weight=1)
        frame_public_keys.grid_rowconfigure(6, weight=1)
        frame_public_keys_label1 = customtkinter.CTkLabel(master=frame_public_keys, text="Public keys",
                                                          font=("Roboto", 20))
        frame_public_keys_label1.grid(row=0, column=0, columnspan=2, sticky="news", pady=(20, 14))

        self.frame_send_puk_table = customtkinter.CTkFrame(master=frame_public_keys)
        self.frame_send_puk_table.grid(row=1, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 5))
        self.frame_send_puk_scroll = customtkinter.CTkScrollableFrame(master=frame_public_keys)
        self.frame_send_puk_scroll.grid(row=2, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 40))
        self.frame_send_puk_table.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="a")
        self.frame_send_puk_scroll.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="a")
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="User ID").grid(row=0, column=0, padx=(10, 0))
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="Key ID").grid(row=0, column=1, columnspan=2)
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="PuK").grid(row=0, column=3, columnspan=2)
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="E-Mail").grid(row=0, column=5, columnspan=2,
                                                                                     padx=(0, 4))
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="Algorithm").grid(row=0, column=7, padx=(0, 24))
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="Time").grid(row=0, column=8, padx=(0, 30))
        self.send_public_key_var = customtkinter.IntVar(0)
        i = 0
        for key, value in keys_gen.dict_public_key_ring.items():
            public_key_val = value[0]
            if len(public_key_val) > 30:
                public_key_val = public_key_val[0:30] + "..."
            customtkinter.CTkRadioButton(master=self.frame_send_puk_scroll, text=key[0], border_width_unchecked=0,
                                         border_width_checked=5, state="disabled",
                                         variable=self.send_public_key_var, value=int(key[1])).grid(row=i,
                                                                                                    column=0)
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=key[1]).grid(row=i, column=1, columnspan=2)
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=public_key_val, wraplength=140).grid(row=i,
                                                                                                                column=3,
                                                                                                                columnspan=2,
                                                                                                                pady=(
                                                                                                                    0,
                                                                                                                    5))
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=value[1], wraplength=140).grid(row=i,
                                                                                                          column=5,
                                                                                                          columnspan=2)
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=value[2]).grid(row=i, column=7)
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=value[3], wraplength=100).grid(row=i,
                                                                                                          column=8)
            i = i + 1

        # Private Keys
        frame_private_keys_label1 = customtkinter.CTkLabel(master=frame_public_keys, text="Private keys",
                                                           font=("Roboto", 20))
        frame_private_keys_label1.grid(row=3, column=0, columnspan=2, sticky="news", pady=(20, 14))

        self.frame_send_prk_table = customtkinter.CTkFrame(master=frame_public_keys)
        self.frame_send_prk_table.grid(row=4, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 5))
        self.frame_send_prk_scroll = customtkinter.CTkScrollableFrame(master=frame_public_keys)
        self.frame_send_prk_scroll.grid(row=5, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 20))
        self.frame_send_prk_table.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="p")
        self.frame_send_prk_scroll.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="p")
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="User ID").grid(row=0, column=0, padx=(10, 0))
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="Key ID").grid(row=0, column=1, columnspan=2)
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="PuK").grid(row=0, column=3, columnspan=2)
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="E(PrK)").grid(row=0, column=5, columnspan=2,
                                                                                     padx=(0, 4))
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="Algorithm").grid(row=0, column=7, padx=(0, 24))
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="Time").grid(row=0, column=8, padx=(0, 30))
        self.send_private_key_var = customtkinter.IntVar(0)
        i = 0
        for key, value in keys_gen.dict_private_key_ring.items():
            public_key_val = value[0]
            if len(public_key_val) > 30:
                public_key_val = public_key_val[0:30] + "..."
            private_key_val = value[1]
            if len(private_key_val) > 30:
                private_key_val = private_key_val[0:30] + "..."
            customtkinter.CTkRadioButton(master=self.frame_send_prk_scroll, text=key[0], border_width_unchecked=0,
                                         border_width_checked=5, state="disabled",
                                         variable=self.send_private_key_var, value=int(key[1])).grid(row=i,
                                                                                                     column=0)
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=key[1]).grid(row=i, column=1, columnspan=2)
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=public_key_val, wraplength=140).grid(row=i,
                                                                                                                column=3,
                                                                                                                columnspan=2,
                                                                                                                pady=(
                                                                                                                    0,
                                                                                                                    5))
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=private_key_val, wraplength=140).grid(row=i,
                                                                                                                 column=5,
                                                                                                                 columnspan=2)
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=value[2]).grid(row=i, column=7)
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=value[3], wraplength=100).grid(row=i,
                                                                                                          column=8)
            i = i + 1

        return frame

    def prompt_user(self, enc_key_id, filename):

        modal = customtkinter.CTkToplevel(self)
        modal.title("Enter password")
        modal.geometry("500x500")
        modal.grab_set()

        x = self.winfo_x()
        y = self.winfo_y()
        modal.geometry("+%d+%d" % (x + 480, y + 160))

        modal_frame = customtkinter.CTkFrame(master=modal)
        modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
        modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
        modal_frame.grid_rowconfigure(3, weight=1)
        modal_frame.grid_rowconfigure(4, weight=1)
        modal_frame.grid_columnconfigure(0, weight=1)
        self.modal_auth_label1 = customtkinter.CTkLabel(master=modal_frame, text="Private key authentication",
                                                        font=("Roboto", 26)).grid(row=0, column=0, stick="news",
                                                                                  pady=20, padx=20)
        self.modal_auth_label2 = customtkinter.CTkLabel(master=modal_frame, text="Please enter key password for key id: "+enc_key_id, font=("Roboto", 16), wraplength=200)
        self.modal_auth_label2.grid(row=1, column=0, stick="news", pady=20, padx=20)
        self.modal_auth_password = customtkinter.StringVar(0)
        self.modal_auth_input1 = customtkinter.CTkEntry(master=modal_frame, placeholder_text="Password", show="*",
                                                        textvariable=self.modal_auth_password)
        self.modal_auth_input1.grid(row=2, column=0, stick="news", pady=(0, 20), padx=20)
        self.wrong_password_label = customtkinter.CTkLabel(modal_frame, text="Wrong password")
        self.wrong_password_label.grid(row=3, column=0)
        self.wrong_password_label.grid_remove()
        modal_button = customtkinter.CTkButton(master=modal_frame, text="Confirm", font=("Roboto", 14),
                                               command=lambda: self.get_password(enc_key_id, modal, filename))
        modal_button.grid(row=4, column=0, stick="ews", padx=20, pady=(0, 20))

    def get_password(self, enc_key_id, modal, filename):
        if keys_io.check_password(enc_key_id, self.modal_auth_password.get()) == "Wrong password":
            self.msg = "Wrong password"
            self.wrong_password_label.grid()
        else:
            modal.destroy()
            self.dec_and_ver(filename)

    def start_dec(self, filename):
        with open(filename, 'r') as file:
            content = file.read()
        if len(content) >= 4:
            last_four_chars = content[-4:]

            file.close()
        content= str(content)
        rad = 0
        enc = 0
        com = 0
        auth = 0
        if last_four_chars[0] == '1':
            rad = 1
        if last_four_chars[1] == '1':
            enc = 1
        if last_four_chars[2] == '1':
            com = 1
        if last_four_chars[3] == '1':
            auth = 1

        parts = content.split("&")
        msg = parts[0]

        if rad == 1:
            msg = bytes.fromhex(msg)
            msg = base64.b64decode(msg)
            msg = msg.decode('utf-8')
        if enc == 1:
            parts1 = msg.split("#*-*#")
            msg = parts1[0]
            enc_sess_key = parts1[1]
            enc_key_id = parts1[2]

            self.prompt_user(enc_key_id, filename)
        else:
            # it was not encrypted, no need for password.
            self.dec_and_ver(filename)

    def dec_and_ver(self, filename):

        with open(filename, 'r') as file:
            content = file.read()

        if len(content) >= 4:
            last_four_chars = content[-4:]

            file.close()

        rad = 0
        enc = 0
        com = 0
        auth = 0
        isValid = ""

        if last_four_chars[0] == '1':
            rad = 1
        if last_four_chars[1] == '1':
            enc = 1
        if last_four_chars[2] == '1':
            com = 1
        if last_four_chars[3] == '1':
            auth = 1

        parts = content.split("&")
        msg = parts[0]

        if rad == 1:
            msg = bytes.fromhex(msg)
            msg = base64.b64decode(msg)
            msg = msg.decode('utf-8')
        if enc == 1:
            parts1 = msg.split("#*-*#")
            msg = parts1[0]
            enc_sess_key = parts1[1]
            enc_key_id = parts1[2]

            username = keys_gen.dict_key_id[enc_key_id]
            private_key = keys_gen.dict_public_key_ring.get((username, enc_key_id))[4]
            # we got pass.

            public_key_algorithm = keys_gen.dict_public_key_ring.get((username, enc_key_id))[2]
            if public_key_algorithm == "RSA":
                cipher_rsa = PKCS1_OAEP.new(private_key)
                decrypted_session_key = cipher_rsa.decrypt(bytes.fromhex(enc_sess_key))
            else:
                encrypted_session_key = enc_sess_key.split(', ')
                encrypted_session_key = elgamal.elgamal.CipherText(int(encrypted_session_key[0][11:]),
                                                                   int(encrypted_session_key[1][:-1]))
                p = private_key.p
                x = private_key.x

                elg_priv_key = elgamal.elgamal.PrivateKey(p, x)
                decrypted_session_key = Elgamal.decrypt(encrypted_session_key, elg_priv_key)

            decrypted_session_key = decrypted_session_key.decode('utf-8')

            decrypted_parts = decrypted_session_key.split("#*-*#")

            session_key = decrypted_parts[0]

            algorithm = int(decrypted_parts[1])
            session_key = bytes.fromhex(session_key)
            # AES

            if algorithm == 1:
                msg = bytes.fromhex(msg)
                eiv = msg[:AES.block_size + 2]
                msg = msg[AES.block_size + 2:]
                cipher_aes = AES.new(session_key, AES.MODE_OPENPGP, eiv)
                msg = cipher_aes.decrypt(msg)
            # CAST
            else:
                msg = bytes.fromhex(msg)
                eiv = msg[:CAST.block_size + 2]
                msg = msg[CAST.block_size + 2:]
                cipher_cast = CAST.new(session_key, CAST.MODE_OPENPGP, eiv)
                msg = cipher_cast.decrypt(msg)
            msg = msg.decode('utf-8')
        if com == 1:
            msg = bytes.fromhex(msg)
            msg = zlib.decompress(msg)
            msg = msg.decode('utf-8')

        if auth == 1:
            parts = msg.split("#*-*#")
            msg = parts[0] + "#*-*#" + parts[1] + "#*-*#" + parts[2]  # start
            encrypted_hash_message = bytes.fromhex(parts[3])

            hash_digest = parts[4]
            auth_key_id = str(parts[5])
            username = keys_gen.dict_key_id[auth_key_id]
            key = keys_gen.dict_public_key_ring.get((username, auth_key_id))[4]
            mail = keys_gen.dict_public_key_ring.get((username, auth_key_id))[1]
            aut_algorithm_id = parts[6]
            signature_time = parts[7]
            self.user_id.configure(text="User ID: " + username)
            self.mail.configure(text="E-Mail: " + mail)
            self.sig_time.configure(text="Signature time: " + signature_time)
            self.small_box.configure(text="Information about the author")
            if aut_algorithm_id == "1":
                # RSA
                try:
                    signature_ok = PKCS1_PSS.new(key).verify(SHA1.new(msg.encode('utf-8')), encrypted_hash_message)
                    isValid = "Signature is valid."
                except:
                    isValid = "Signature is invalid."

            elif aut_algorithm_id == "2":
                # DSS
                try:
                    signature_ok = DSS.new(key, 'fips-186-3').verify(SHA1.new(msg.encode('utf-8')), encrypted_hash_message)
                    isValid = "Signature is valid."
                except:
                    isValid = "Signature is invalid."
        self.verification_ok.configure(text=isValid)
        parts = msg.split("#*-*#")
        msg = parts[0]
        time = parts[1]
        filename = parts[2]

        self.frame_receive_textarea.configure(state="normal")
        self.frame_receive_textarea.delete("0.0", customtkinter.END)
        self.frame_receive_textarea.insert("0.0", msg)
        self.decrypted_text = msg
        self.decrypted_name = "decrypted_" + filename
        self.frame_receive_textarea.configure(state="disabled")

    def save_message(self):
        directory = tkinter.filedialog.askdirectory(initialdir="./DecryptedMessages")
        if directory == "":
            return
        else:
           file = directory + "/"+self.decrypted_name
           f = open(file, "w")
           f.write(self.decrypted_text)
           f.close()

    def select_file(self):

        filename = tkinter.filedialog.askopenfilename(
            title='Open a .txt file',
            initialdir='./MessageBox/',
        )
        self.small_box.configure(text="")
        self.user_id.configure(text="")
        self.mail.configure(text="")
        self.sig_time.configure(text="")
        self.verification_ok.configure(text="")

        if filename:
            self.btn_save_message.configure(self, state="normal")
            self.start_dec(filename)

        else:
            self.btn_save_message.configure(self, state="disabled")
            return

    def load_frame_send(self, old_frame: customtkinter.CTkFrame):
        self.loaded_frame = "send"
        if old_frame:
            old_frame.destroy()

        # Frame init
        frame = customtkinter.CTkFrame(master=self)
        frame.grid_columnconfigure(0, weight=0)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=3)
        frame.grid_rowconfigure((0, 1, 2, 3), weight=1)
        frame.pack(expand=True, fill="both")

        # Sidebar
        frame_sidebar = customtkinter.CTkFrame(master=frame, width=140, corner_radius=0)
        frame_sidebar.grid(row=0, column=0, rowspan=4, sticky="news")
        frame_sidebar.grid_rowconfigure(6, weight=1)
        label_main = customtkinter.CTkLabel(master=frame_sidebar, text="PGP ZP Project", font=("Roboto Bold", 20))
        label_main.grid(row=0, column=0, padx=20, pady=(20, 10), stick="news")
        button_keys_menu = customtkinter.CTkButton(master=frame_sidebar, text="Keys Menu", font=("Roboto", 14),
                                                   command=lambda: self.transition("32"))
        button_keys_menu.grid(row=1, column=0, padx=20, pady=(30, 10), stick="news")
        button_send_menu = customtkinter.CTkButton(master=frame_sidebar, text="Send Message", font=("Roboto", 14),
                                                   state="disabled")
        button_send_menu.grid(row=2, column=0, padx=20, pady=10, stick="news")
        button_receive_menu = customtkinter.CTkButton(master=frame_sidebar, text="Receive Message", font=("Roboto", 14),
                                                      command=lambda: self.transition("34"))
        button_receive_menu.grid(row=3, column=0, padx=20, pady=10, stick="news")

        appearance_frame = customtkinter.CTkFrame(master=frame_sidebar)
        appearance_frame.grid(row=4, rowspan=2, column=0, padx=20, pady=(180, 20), stick="sew")
        customtkinter.CTkLabel(master=appearance_frame, text="Change Appearance", font=("Roboto", 14)).grid(row=0,
                                                                                                            column=0,
                                                                                                            padx=10,
                                                                                                            pady=(
                                                                                                                10, 0),
                                                                                                            stick="new")
        self.color_option_var = customtkinter.StringVar(0)
        self.color_option_var.set("Switch Color")
        self.color_option = customtkinter.CTkOptionMenu(master=appearance_frame, values=["Green", "Blue", "Dark Blue"],
                                                        command=self.choose_color, font=("Roboto", 14),
                                                        variable=self.color_option_var,
                                                        dropdown_font=("Roboto", 12))
        self.color_option.grid(row=1, column=0, padx=10, pady=(10, 0), stick="news")
        button_switch = customtkinter.CTkButton(master=appearance_frame, text="Switch Mode", font=("Roboto", 14),
                                                command=self.switch_appearance)
        button_switch.grid(row=2, column=0, pady=(10, 10), padx=10, stick="sew")
        button_back = customtkinter.CTkButton(master=frame_sidebar, text="Start Menu", font=("Roboto", 14),
                                              command=lambda: self.transition("31"))
        button_back.grid(row=6, column=0, padx=20, pady=(20, 40), stick="sew")

        # Send Message
        frame_send_message = customtkinter.CTkFrame(master=frame)
        frame_send_message.grid(row=0, column=1, rowspan=4, sticky="news", pady=20, padx=20)
        frame_send_message.grid_columnconfigure((0, 1, 2, 3), weight=1)
        frame_send_message.grid_rowconfigure(7, weight=1)

        frame_send_message_label1 = customtkinter.CTkLabel(master=frame_send_message, text="Send Message",
                                                           font=("Roboto", 20))
        frame_send_message_label1.grid(row=0, column=0, columnspan=4, sticky="news", pady=20)

        self.frame_send_textarea = customtkinter.CTkTextbox(master=frame_send_message, wrap="word")
        self.frame_send_textarea.bind("<Key>", self.calculate)
        self.frame_send_textarea.grid(row=1, column=0, columnspan=4, stick="news", padx=20)

        frame_send_message_label2 = customtkinter.CTkLabel(master=frame_send_message, text="Choose following options:",
                                                           font=("Roboto", 16))
        frame_send_message_label2.grid(row=2, column=0, columnspan=4, sticky="news", pady=20)

        self.switch_enc_var = customtkinter.StringVar()
        self.frame_send_switch1 = customtkinter.CTkSwitch(master=frame_send_message, variable=self.switch_enc_var,
                                                          text="Encryption", onvalue="on", offvalue="off",
                                                          state="disabled",
                                                          command=self.toggle_encryption)
        self.frame_send_switch1.grid(row=3, column=0, columnspan=2, stick="w", padx=(30, 0), pady=(0, 10))
        self.switch_aut_var = customtkinter.StringVar()
        self.frame_send_switch2 = customtkinter.CTkSwitch(master=frame_send_message, variable=self.switch_aut_var,
                                                          text="Authentication", onvalue="on", offvalue="off",
                                                          state="disabled",
                                                          command=self.toggle_authentication)
        self.frame_send_switch2.grid(row=3, column=2, columnspan=2, stick="w", pady=(0, 10))
        self.switch_com_var = customtkinter.StringVar()
        self.frame_send_switch3 = customtkinter.CTkSwitch(master=frame_send_message, variable=self.switch_com_var,
                                                          state="disabled",
                                                          text="Compression", onvalue="on", offvalue="off")
        self.frame_send_switch3.grid(row=4, column=0, columnspan=2, stick="w", padx=(30, 0))
        self.switch_rad_var = customtkinter.StringVar()
        self.frame_send_switch4 = customtkinter.CTkSwitch(master=frame_send_message, variable=self.switch_rad_var,
                                                          state="disabled",
                                                          text="Radix64", onvalue="on", offvalue="off")
        self.frame_send_switch4.grid(row=4, column=2, columnspan=2, stick="w")

        frame_send_message_label3 = customtkinter.CTkLabel(master=frame_send_message,
                                                           text="Choose encryption algorythm:",
                                                           font=("Roboto", 16))
        frame_send_message_label3.grid(row=5, column=0, columnspan=4, sticky="news", pady=(40, 20))

        self.alg_var = customtkinter.IntVar(0)

        self.frame_send_radio1 = customtkinter.CTkRadioButton(master=frame_send_message, text="AES", state="disabled",
                                                              variable=self.alg_var, value="1",
                                                              border_width_unchecked=2)
        self.frame_send_radio1.grid(row=6, column=0, columnspan=2, stick="e", padx=10)
        self.frame_send_radio2 = customtkinter.CTkRadioButton(master=frame_send_message, text="CAST5", state="disabled",
                                                              variable=self.alg_var, value="2",
                                                              border_width_unchecked=2)
        self.frame_send_radio2.grid(row=6, column=2, columnspan=2, stick="w", padx=10)
        self.frame_send_button = customtkinter.CTkButton(master=frame_send_message, text="Send", font=("Roboto", 14),
                                                         state="disabled", command=self.send_message)
        self.frame_send_button.grid(row=7, column=0, columnspan=4, padx=20, stick="wes", pady=20)

        # Tables
        frame_public_keys = customtkinter.CTkFrame(master=frame)
        frame_public_keys.grid(row=0, column=2, rowspan=7, sticky="news", pady=20, padx=(0, 20))
        frame_public_keys.grid_columnconfigure((0, 1), weight=1)
        frame_public_keys.grid_rowconfigure(6, weight=1)
        frame_public_keys_label1 = customtkinter.CTkLabel(master=frame_public_keys, text="Public keys",
                                                          font=("Roboto", 20))
        frame_public_keys_label1.grid(row=0, column=0, columnspan=2, sticky="news", pady=(20, 14))

        self.frame_send_puk_table = customtkinter.CTkFrame(master=frame_public_keys)
        self.frame_send_puk_table.grid(row=1, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 5))
        self.frame_send_puk_scroll = customtkinter.CTkScrollableFrame(master=frame_public_keys)
        self.frame_send_puk_scroll.grid(row=2, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 40))
        self.frame_send_puk_table.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="a")
        self.frame_send_puk_scroll.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="a")
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="User ID").grid(row=0, column=0, padx=(10, 0))
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="Key ID").grid(row=0, column=1, columnspan=2)
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="PuK").grid(row=0, column=3, columnspan=2)
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="E-Mail").grid(row=0, column=5, columnspan=2,
                                                                                     padx=(0, 4))
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="Algorithm").grid(row=0, column=7, padx=(0, 24))
        customtkinter.CTkLabel(master=self.frame_send_puk_table, text="Time").grid(row=0, column=8, padx=(0, 30))
        self.send_public_key_var = customtkinter.IntVar(0)
        i = 0
        for key, value in keys_gen.dict_public_key_ring.items():
            public_key_val = value[0]
            if len(public_key_val) > 30:
                public_key_val = public_key_val[0:30] + "..."
            customtkinter.CTkRadioButton(master=self.frame_send_puk_scroll, text=key[0], border_width_unchecked=0,
                                         border_width_checked=5, state="disabled",
                                         variable=self.send_public_key_var, value=int(key[1])).grid(row=i,
                                                                                                    column=0)
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=key[1]).grid(row=i, column=1, columnspan=2)
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=public_key_val, wraplength=140).grid(row=i,
                                                                                                                column=3,
                                                                                                                columnspan=2,
                                                                                                                pady=(
                                                                                                                    0,
                                                                                                                    5))
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=value[1], wraplength=140).grid(row=i,
                                                                                                          column=5,
                                                                                                          columnspan=2)
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=value[2]).grid(row=i, column=7)
            customtkinter.CTkLabel(master=self.frame_send_puk_scroll, text=value[3], wraplength=100).grid(row=i,
                                                                                                          column=8)
            i = i + 1

        # Private Keys
        frame_private_keys_label1 = customtkinter.CTkLabel(master=frame_public_keys, text="Private keys",
                                                           font=("Roboto", 20))
        frame_private_keys_label1.grid(row=3, column=0, columnspan=2, sticky="news", pady=(20, 14))

        self.frame_send_prk_table = customtkinter.CTkFrame(master=frame_public_keys)
        self.frame_send_prk_table.grid(row=4, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 5))
        self.frame_send_prk_scroll = customtkinter.CTkScrollableFrame(master=frame_public_keys)
        self.frame_send_prk_scroll.grid(row=5, column=0, columnspan=2, sticky="news", padx=20, pady=(0, 20))
        self.frame_send_prk_table.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="p")
        self.frame_send_prk_scroll.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6, 7, 8), weight=1, uniform="p")
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="User ID").grid(row=0, column=0, padx=(10, 0))
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="Key ID").grid(row=0, column=1, columnspan=2)
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="PuK").grid(row=0, column=3, columnspan=2)
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="E(PrK)").grid(row=0, column=5, columnspan=2,
                                                                                     padx=(0, 4))
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="Algorithm").grid(row=0, column=7, padx=(0, 24))
        customtkinter.CTkLabel(master=self.frame_send_prk_table, text="Time").grid(row=0, column=8, padx=(0, 30))
        self.send_private_key_var = customtkinter.IntVar(0)
        i = 0
        for key, value in keys_gen.dict_private_key_ring.items():
            public_key_val = value[0]
            if len(public_key_val) > 30:
                public_key_val = public_key_val[0:30] + "..."
            private_key_val = value[1]
            if len(private_key_val) > 30:
                private_key_val = private_key_val[0:30] + "..."
            customtkinter.CTkRadioButton(master=self.frame_send_prk_scroll, text=key[0], border_width_unchecked=0,
                                         border_width_checked=5, state="disabled",
                                         variable=self.send_private_key_var, value=int(key[1])).grid(row=i,
                                                                                                     column=0)
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=key[1]).grid(row=i, column=1, columnspan=2)
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=public_key_val, wraplength=140).grid(row=i,
                                                                                                                column=3,
                                                                                                                columnspan=2,
                                                                                                                pady=(
                                                                                                                    0,
                                                                                                                    5))
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=private_key_val, wraplength=140).grid(row=i,
                                                                                                                 column=5,
                                                                                                                 columnspan=2)
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=value[2]).grid(row=i, column=7)
            customtkinter.CTkLabel(master=self.frame_send_prk_scroll, text=value[3], wraplength=100).grid(row=i,
                                                                                                          column=8)
            i = i + 1

        return frame

    def __init__(self):
        super().__init__()
        self.frame_send_switch1 = None
        self.frame_send_textarea = None
        self.appearance = "dark"
        self.default_color = "#2fa572"
        self.default_background_dark = "#2b2b2b"
        self.default_background_light = "#dbdbdb"
        self.current_image = "dark_green.png"
        self.msg = ""

        self.modal_export_input1 = None
        self.modal_export_input2 = None
        self.modal_password_input1 = None
        self.modal_password_input2 = None
        self.frame_create_keys_username = None
        self.frame_create_keys_mail = None
        self.alg_radio = None
        self.key_radio = None
        self.public_key_var = None
        self.private_key_var = None

        self.title("ZP Projekat PGP.py")
        self.geometry("1460x820")
        self.resizable(False, False)

        keys_gen.create_random_keys()

        self.frame_welcome = self.load_frame_welcome(None)

        self.frame_keys = None
        self.frame_send = None

        self.frame_receive = None

        self.receive_password = ""

        self.loaded_frame = "start"

    def enable_button(self, button: customtkinter.CTkButton):
        button.configure(state="normal")

    def toggle_encryption(self):
        if (self.switch_enc_var.get() == "on"):
            self.frame_send_puk_table.configure(fg_color=self.default_color)
            for element in self.frame_send_puk_scroll.winfo_children():
                if isinstance(element, customtkinter.CTkRadioButton):
                    element.configure(state="normal", border_width_unchecked=1, border_width_checked=5)
            self.frame_send_radio1.configure(state="normal")
            self.frame_send_radio2.configure(state="normal")

            self.alg_var.set(1)
            self.frame_send_radio1.select()

            first_child = self.frame_send_puk_scroll.winfo_children()[0]
            first_child.select()
            self.send_public_key_var.set(first_child.cget("value"))
        else:
            self.frame_send_puk_table.configure(
                fg_color=self.default_background_dark if self.appearance == "dark" else self.default_background_light)
            self.send_public_key_var.set(0)
            for element in self.frame_send_puk_scroll.winfo_children():
                if isinstance(element, customtkinter.CTkRadioButton):
                    element.configure(state="disabled", border_width_unchecked=0, border_width_checked=0)
            self.frame_send_radio1.configure(state="disabled")
            self.frame_send_radio2.configure(state="disabled")
            self.alg_var.set(0)

    def toggle_authentication(self):
        if (self.switch_aut_var.get() == "on"):
            self.frame_send_prk_table.configure(fg_color=self.default_color)
            for element in self.frame_send_prk_scroll.winfo_children():
                if isinstance(element, customtkinter.CTkRadioButton):
                    element.configure(state="normal", border_width_unchecked=1, border_width_checked=5)

            first_child = self.frame_send_prk_scroll.winfo_children()[0]
            first_child.select()
            self.send_private_key_var.set(first_child.cget("value"))
        else:
            self.frame_send_prk_table.configure(
                fg_color=self.default_background_dark if self.appearance == "dark" else self.default_background_light)
            self.send_private_key_var.set(0)
            for element in self.frame_send_prk_scroll.winfo_children():
                if isinstance(element, customtkinter.CTkRadioButton):
                    element.configure(state="disabled", border_width_unchecked=0, border_width_checked=0)

    def transition(self, from_to):
        if from_to == "12":
            self.frame_keys = self.load_frame_keys(self.frame_welcome)
        elif from_to == "21":
            self.frame_welcome = self.load_frame_welcome(self.frame_keys)
        elif from_to == "23":
            self.frame_send = self.load_frame_send(self.frame_keys)
        elif from_to == "24":
            self.frame_receive = self.load_frame_receive(self.frame_keys)
        elif from_to == "34":
            self.frame_receive = self.load_frame_receive(self.frame_send)
        elif from_to == "42":
            self.frame_keys = self.load_frame_keys(self.frame_receive)
        elif from_to == "41":
            self.frame_welcome = self.load_frame_welcome(self.frame_receive)
        elif from_to == "43":
            self.frame_send = self.load_frame_send(self.frame_receive)
        elif from_to == "32":
            self.frame_keys = self.load_frame_keys(self.frame_send)
        elif from_to == "31":
            self.frame_welcome = self.load_frame_welcome(self.frame_send)
        elif from_to == "33":
            self.frame_send = self.load_frame_send(self.frame_send)
        elif from_to == "22":
            self.frame_keys = self.load_frame_keys(self.frame_keys)

    def enter_password(self):
        message = ""
        for key, value in keys_gen.dict_public_key_ring.items():
            if key[0] == self.frame_create_keys_username.get() and value[1] == self.frame_create_keys_mail.get():
                message = "Username and E-Mail\nare already in use."
                break
        modal = customtkinter.CTkToplevel(self)
        modal.title("Create Key")
        modal.geometry("500x500")
        modal.grab_set()

        x = self.winfo_x()
        y = self.winfo_y()
        modal.geometry("+%d+%d" % (x + 480, y + 160))
        modal_frame = customtkinter.CTkFrame(master=modal)
        modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
        if message != "":
            modal_frame.grid_rowconfigure(0, weight=0)
            modal_frame.grid_rowconfigure(1, weight=1)
            modal_frame.grid_columnconfigure(0, weight=1)
            customtkinter.CTkLabel(master=modal_frame, text=message, font=("Roboto", 26)).grid(
                row=0, column=0, stick="news", pady=20, padx=20)
            modal_button = customtkinter.CTkButton(master=modal_frame, text="Back", font=("Roboto", 14),
                                                   command=lambda: self.close_modal(modal))
            modal_button.grid(row=2, column=0, stick="ews", padx=20, pady=(0, 20))
        elif len(self.frame_create_keys_username.get()) == 0 or len(self.frame_create_keys_mail.get()) == 0 or \
                (self.alg_radio.get() != 1 and self.alg_radio.get() != 2) or (
                self.key_radio.get() != 1024 and self.key_radio.get() != 2048):
            modal_frame.grid_rowconfigure(0, weight=0)
            modal_frame.grid_rowconfigure(1, weight=1)
            modal_frame.grid_columnconfigure(0, weight=1)
            customtkinter.CTkLabel(master=modal_frame, text="You must fill all fields", font=("Roboto", 26)).grid(
                row=0, column=0, stick="news", pady=20, padx=20)
            modal_button = customtkinter.CTkButton(master=modal_frame, text="Back", font=("Roboto", 14),
                                                   command=lambda: self.close_modal(modal))
            modal_button.grid(row=2, column=0, stick="ews", padx=20, pady=(0, 20))
        else:
            modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
            modal_frame.grid_rowconfigure(3, weight=1)
            modal_frame.grid_columnconfigure(0, weight=1)
            customtkinter.CTkLabel(master=modal_frame, text="Please enter the password", font=("Roboto", 26)).grid(
                row=0, column=0, stick="news", pady=20, padx=20)
            customtkinter.CTkLabel(master=modal_frame, text="User: " + self.frame_create_keys_username.get()
                                                            + "\nE-Mail: " + self.frame_create_keys_mail.get(),
                                   font=("Roboto", 16)).grid(
                row=1, column=0, stick="news", pady=20, padx=20)
            self.modal_password_input1 = customtkinter.CTkEntry(master=modal_frame, placeholder_text="Password",
                                                                show="*")
            self.modal_password_input1.grid(row=2, column=0, stick="news", pady=20, padx=20)
            modal_button = customtkinter.CTkButton(master=modal_frame, text="Confirm", font=("Roboto", 14),
                                                   command=lambda: self.submit_form_create_key(
                                                       self.frame_create_keys_username.get(),
                                                       self.frame_create_keys_mail.get(),
                                                       self.alg_radio.get(), self.key_radio.get(),
                                                       self.modal_password_input1.get(),
                                                       modal))
            modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))

    def submit_form_create_key(self, username: str, email: str, alg: int, size: int, password: str,
                               modal: customtkinter.CTkToplevel):
        keys_gen.create_key_pair(username, email, alg, size, password)
        self.close_modal_refresh(modal, "keys")

    def import_key(self):
        filepath = tkinter.filedialog.askopenfilename(
            title='Open a .pem file',
            initialdir='./KeyBox',
            filetypes=[('Pem files', '*.pem')])
        if filepath == "":
            return
        file = open(filepath, "r")
        import_key = file.read()
        file.close()
        if import_key[0:27] == "-----BEGIN DSA PRIVATE-----" or import_key[0:27] == "-----BEGIN RSA PRIVATE-----":
            modal = customtkinter.CTkToplevel(self)
            modal.title("Import private key")
            modal.geometry("500x500")
            modal.grab_set()

            x = self.winfo_x()
            y = self.winfo_y()
            modal.geometry("+%d+%d" % (x + 480, y + 160))

            modal_frame = customtkinter.CTkFrame(master=modal)
            modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
            modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
            modal_frame.grid_rowconfigure(3, weight=1)
            modal_frame.grid_columnconfigure(0, weight=1)
            self.modal_export_label1 = customtkinter.CTkLabel(master=modal_frame, text="Private key import",
                                                              font=("Roboto", 26)).grid(row=0, column=0, stick="news",
                                                                                        pady=20, padx=20)
            self.modal_export_label2 = customtkinter.CTkLabel(master=modal_frame, text="Please enter key password",
                                                              font=("Roboto", 16))
            self.modal_export_label2.grid(row=1, column=0, stick="news", pady=20, padx=20)
            self.modal_import_password = customtkinter.StringVar(0)
            self.modal_export_input1 = customtkinter.CTkEntry(master=modal_frame, placeholder_text="Password", show="*",
                                                              textvariable=self.modal_import_password)
            self.modal_export_input1.grid(row=2, column=0, stick="news", pady=(0, 20), padx=20)
            modal_button = customtkinter.CTkButton(master=modal_frame, text="Confirm", font=("Roboto", 14),
                                                   command=lambda: self.import_private(modal, import_key))
            modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))
        else:
            message = keys_io.import_key(import_key, "public", "")
            modal = customtkinter.CTkToplevel(self)
            modal.title("Import public key")
            modal.geometry("500x500")
            modal.grab_set()

            x = self.winfo_x()
            y = self.winfo_y()
            modal.geometry("+%d+%d" % (x + 480, y + 160))

            modal_frame = customtkinter.CTkFrame(master=modal)
            modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
            modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
            modal_frame.grid_rowconfigure(3, weight=1)
            modal_frame.grid_columnconfigure(0, weight=1)
            self.modal_export_label1 = customtkinter.CTkLabel(master=modal_frame, text="Public key import",
                                                              font=("Roboto", 26)).grid(row=0, column=0, stick="news",
                                                                                        pady=20, padx=20)
            self.modal_export_label2 = customtkinter.CTkLabel(master=modal_frame, text=message, font=("Roboto", 16),
                                                              wraplength=400)
            self.modal_export_label2.grid(row=1, column=0, stick="news", pady=20, padx=20)
            modal_button = customtkinter.CTkButton(master=modal_frame, text="Back", font=("Roboto", 14),
                                                   command=lambda: self.close_modal_refresh(modal, "keys"))
            modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))

    def import_private(self, modal_old: customtkinter.CTkToplevel, import_key: str):
        modal_old.destroy()
        message = keys_io.import_key(import_key, "private", self.modal_import_password.get())

        modal = customtkinter.CTkToplevel(self)
        modal.title("Export public key")
        modal.geometry("500x500")
        modal.grab_set()

        x = self.winfo_x()
        y = self.winfo_y()
        modal.geometry("+%d+%d" % (x + 480, y + 160))

        modal_frame = customtkinter.CTkFrame(master=modal)
        modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
        modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
        modal_frame.grid_rowconfigure(3, weight=1)
        modal_frame.grid_columnconfigure(0, weight=1)
        self.modal_export_label1 = customtkinter.CTkLabel(master=modal_frame, text="Public key export",
                                                          font=("Roboto", 26)).grid(row=0, column=0, stick="news",
                                                                                    pady=20, padx=20)
        self.modal_export_label2 = customtkinter.CTkLabel(master=modal_frame, text=message, wraplength=400,
                                                          font=("Roboto", 16))
        self.modal_export_label2.grid(row=1, column=0, stick="news", pady=20, padx=20)
        modal_button = customtkinter.CTkButton(master=modal_frame, text="Back", font=("Roboto", 14),
                                               command=lambda: self.close_modal_refresh(modal, "keys"))
        modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))

    def export(self):
        if self.private_key_var.get() == 0:
            directory = tkinter.filedialog.askdirectory(initialdir="./KeyBox")
            if directory == "":
                self.public_key_var.set(0)
                if self.private_key_var.get() == 0 and self.public_key_var.get() == 0:
                    self.frame_private_keys_button2.configure(state="disabled")
                return
            message = keys_io.export_key(self.public_key_var.get(), "public", "", directory)
            self.public_key_var.set(0)
            modal = customtkinter.CTkToplevel(self)
            modal.title("Export public key")
            modal.geometry("500x500")
            modal.grab_set()

            x = self.winfo_x()
            y = self.winfo_y()
            modal.geometry("+%d+%d" % (x + 480, y + 160))

            modal_frame = customtkinter.CTkFrame(master=modal)
            modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
            modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
            modal_frame.grid_rowconfigure(3, weight=1)
            modal_frame.grid_columnconfigure(0, weight=1)
            self.modal_export_label1 = customtkinter.CTkLabel(master=modal_frame, text="Public key export",
                                                              font=("Roboto", 26)).grid(row=0, column=0, stick="news",
                                                                                        pady=20, padx=20)
            self.modal_export_label2 = customtkinter.CTkLabel(master=modal_frame, text=message, font=("Roboto", 16),
                                                              wraplength=400)
            self.modal_export_label2.grid(row=1, column=0, stick="news", pady=20, padx=20)
            modal_button = customtkinter.CTkButton(master=modal_frame, text="Back", font=("Roboto", 14),
                                                   command=lambda: self.close_modal(modal))
            modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))
        else:
            modal = customtkinter.CTkToplevel(self)
            modal.title("Export private key")
            modal.geometry("500x500")
            modal.grab_set()

            x = self.winfo_x()
            y = self.winfo_y()
            modal.geometry("+%d+%d" % (x + 480, y + 160))

            modal_frame = customtkinter.CTkFrame(master=modal)
            modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
            modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
            modal_frame.grid_rowconfigure(3, weight=1)
            modal_frame.grid_columnconfigure(0, weight=1)
            self.modal_export_label1 = customtkinter.CTkLabel(master=modal_frame, text="Private key export",
                                                              font=("Roboto", 26)).grid(row=0, column=0, stick="news",
                                                                                        pady=20, padx=20)
            self.modal_export_label2 = customtkinter.CTkLabel(master=modal_frame, text="Please enter key password",
                                                              font=("Roboto", 16))
            self.modal_export_label2.grid(row=1, column=0, stick="news", pady=20, padx=20)
            self.modal_export_password = customtkinter.StringVar(0)
            self.modal_export_input1 = customtkinter.CTkEntry(master=modal_frame, placeholder_text="Password", show="*",
                                                              textvariable=self.modal_export_password)
            self.modal_export_input1.grid(row=2, column=0, stick="news", pady=(0, 20), padx=20)
            modal_button = customtkinter.CTkButton(master=modal_frame, text="Confirm", font=("Roboto", 14),
                                                   command=lambda: self.export_private(modal))
            modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))

    def export_private(self, modal_old: customtkinter.CTkToplevel):
        modal_old.destroy()
        if (keys_io.check_password(self.private_key_var.get(), self.modal_export_password.get()) != "Wrong password"):
            directory = tkinter.filedialog.askdirectory(initialdir="./KeyBox")
            if directory == "":
                self.private_key_var.set(0)
                if self.private_key_var.get() == 0 and self.public_key_var.get() == 0:
                    self.frame_private_keys_button2.configure(state="disabled")
                return
            message = keys_io.export_key(self.private_key_var.get(), "private", self.modal_export_password.get(),
                                         directory)
        else:
            message = "Wrong password"
        self.private_key_var.set(0)

        modal = customtkinter.CTkToplevel(self)
        modal.title("Export public key")
        modal.geometry("500x500")
        modal.grab_set()

        x = self.winfo_x()
        y = self.winfo_y()
        modal.geometry("+%d+%d" % (x + 480, y + 160))

        modal_frame = customtkinter.CTkFrame(master=modal)
        modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
        modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
        modal_frame.grid_rowconfigure(3, weight=1)
        modal_frame.grid_columnconfigure(0, weight=1)
        self.modal_export_label1 = customtkinter.CTkLabel(master=modal_frame, text="Public key export",
                                                          font=("Roboto", 26)).grid(row=0, column=0, stick="news",
                                                                                    pady=20, padx=20)
        self.modal_export_label2 = customtkinter.CTkLabel(master=modal_frame, text=message, wraplength=400,
                                                          font=("Roboto", 16))
        self.modal_export_label2.grid(row=1, column=0, stick="news", pady=20, padx=20)
        modal_button = customtkinter.CTkButton(master=modal_frame, text="Back", font=("Roboto", 14),
                                               command=lambda: self.close_modal_disable(modal))
        modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))

    def delete_key(self):
        keys_gen.delete_key_pair(str(self.delete_key_var.get()))
        temp = str(self.delete_key_var.get())
        self.delete_key_var.set(0)
        modal = customtkinter.CTkToplevel(self)
        modal.title("Delete Key Pair")
        modal.geometry("500x500")
        modal.grab_set()

        x = self.winfo_x()
        y = self.winfo_y()
        modal.geometry("+%d+%d" % (x + 480, y + 160))

        modal_frame = customtkinter.CTkFrame(master=modal)
        modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
        modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
        modal_frame.grid_rowconfigure(3, weight=1)
        modal_frame.grid_columnconfigure(0, weight=1)
        customtkinter.CTkLabel(master=modal_frame, text="Key deleted",
                               font=("Roboto", 26)).grid(row=0, column=0, stick="news", pady=20, padx=20)
        customtkinter.CTkLabel(master=modal_frame, text="Key ID: " + temp,
                               font=("Roboto", 16)).grid(row=1, column=0, stick="news", pady=20, padx=20)
        modal_button = customtkinter.CTkButton(master=modal_frame, text="Confirm", font=("Roboto", 14),
                                               command=lambda: self.close_modal_refresh(modal, "keys"))
        modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))

    def close_modal(self, modal: customtkinter.CTkToplevel):
        modal.destroy()

    def close_modal_refresh(self, modal: customtkinter, frame: str):
        modal.destroy()
        if frame == "keys":
            self.transition("22")

    def close_modal_disable(self, modal: customtkinter):
        if self.private_key_var.get() == 0 and self.public_key_var.get() == 0:
            self.frame_private_keys_button2.configure(state="disabled")
        self.close_modal(modal)

    def switch_appearance(self):
        if self.appearance == "dark":
            customtkinter.set_appearance_mode("Light")
            self.appearance = "light"
        else:
            customtkinter.set_appearance_mode("Dark")
            self.appearance = "dark"
        if self.loaded_frame == "send":
            if self.switch_enc_var.get() == "off":
                self.frame_send_puk_table.configure(
                    fg_color=self.default_background_dark if self.appearance == "dark" else self.default_background_light)
            if self.switch_aut_var.get() == "off":
                self.frame_send_prk_table.configure(
                    fg_color=self.default_background_dark if self.appearance == "dark" else self.default_background_light)

    def calculate(self, event):
        if len(str(self.frame_send_textarea.get("1.0", customtkinter.END))) < 3:
            self.frame_send_button.configure(state="disabled")
            self.frame_send_switch1.configure(state="disabled")
            self.frame_send_switch2.configure(state="disabled")
            self.frame_send_switch3.configure(state="disabled")
            self.frame_send_switch4.configure(state="disabled")

            self.switch_enc_var.set("off")
            self.switch_aut_var.set("off")
            self.switch_rad_var.set("off")
            self.switch_com_var.set("off")

            self.toggle_encryption()
            self.toggle_authentication()

            self.frame_send_button.configure(state="disabled")
        else:
            self.frame_send_switch1.configure(state="normal")
            self.frame_send_switch2.configure(state="normal")
            self.frame_send_switch3.configure(state="normal")
            self.frame_send_switch4.configure(state="normal")
            self.frame_send_button.configure(state="normal")

    def send_message(self):
        message = self.frame_send_textarea.get("1.0", customtkinter.END)
        message = message[:-1]
        if (self.private_key_var.get() != 0 or self.switch_aut_var.get() == "on"):
            modal = customtkinter.CTkToplevel(self)
            modal.title("Enter password")
            modal.geometry("500x500")
            modal.grab_set()

            x = self.winfo_x()
            y = self.winfo_y()
            modal.geometry("+%d+%d" % (x + 480, y + 160))

            modal_frame = customtkinter.CTkFrame(master=modal)
            modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
            modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
            modal_frame.grid_rowconfigure(3, weight=1)
            modal_frame.grid_columnconfigure(0, weight=1)
            self.modal_auth_label1 = customtkinter.CTkLabel(master=modal_frame, text="Private key authentication",
                                                            font=("Roboto", 26)).grid(row=0, column=0, stick="news",
                                                                                      pady=20, padx=20)
            self.modal_auth_label2 = customtkinter.CTkLabel(master=modal_frame, text="Please enter key password",
                                                            font=("Roboto", 16))
            self.modal_auth_label2.grid(row=1, column=0, stick="news", pady=20, padx=20)
            self.modal_auth_password = customtkinter.StringVar(0)
            self.modal_auth_input1 = customtkinter.CTkEntry(master=modal_frame, placeholder_text="Password", show="*",
                                                            textvariable=self.modal_auth_password)
            self.modal_auth_input1.grid(row=2, column=0, stick="news", pady=(0, 20), padx=20)
            modal_button = customtkinter.CTkButton(master=modal_frame, text="Confirm", font=("Roboto", 14),
                                                   command=lambda: self.send_auth(modal, message))
            modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))
        else:
            directory = tkinter.filedialog.askdirectory(initialdir="./MessageBox")
            if directory == "":
                return
            message, filename = pgp_message.send_message(message, self.send_public_key_var.get(),
                                                         self.send_private_key_var.get(),
                                                         self.alg_var.get(), self.switch_com_var.get(),
                                                         self.switch_rad_var.get())

            filename = directory + "/" + filename
            file = open(filename, "w")
            file.write(message)
            file.close()

    def send_auth(self, modal_old: customtkinter.CTkToplevel, message: str):
        modal_old.destroy()
        if (keys_io.check_password(self.send_private_key_var.get(),
                                   self.modal_auth_password.get()) != "Wrong password"):
            directory = tkinter.filedialog.askdirectory(initialdir="./MessageBox")
            if directory == "":
                return
            message, filename = pgp_message.send_message(message, self.send_public_key_var.get(),
                                                         self.send_private_key_var.get(),
                                                         self.alg_var.get(), self.switch_com_var.get(),
                                                         self.switch_rad_var.get())

            filename = directory + "/" + filename
            file = open(filename, "w")
            file.write(message)
            file.close()

            message = "Message sent successfuly\nFile: " + filename
        else:
            message = "Wrong password"
        self.private_key_var.set(0)

        modal = customtkinter.CTkToplevel(self)
        modal.title("Export public key")
        modal.geometry("500x500")
        modal.grab_set()

        x = self.winfo_x()
        y = self.winfo_y()
        modal.geometry("+%d+%d" % (x + 480, y + 160))

        modal_frame = customtkinter.CTkFrame(master=modal)
        modal_frame.pack(padx=20, pady=20, fill="both", expand=True)
        modal_frame.grid_rowconfigure((0, 1, 2), weight=0)
        modal_frame.grid_rowconfigure(3, weight=1)
        modal_frame.grid_columnconfigure(0, weight=1)
        self.modal_auth_label1 = customtkinter.CTkLabel(master=modal_frame, text="Private key authentication",
                                                        font=("Roboto", 26)).grid(row=0, column=0, stick="news",
                                                                                  pady=20, padx=20)
        self.modal_auth_label2 = customtkinter.CTkLabel(master=modal_frame, text=message, wraplength=400,
                                                        font=("Roboto", 16))
        self.modal_auth_label2.grid(row=1, column=0, stick="news", pady=20, padx=20)
        modal_button = customtkinter.CTkButton(master=modal_frame, text="Back", font=("Roboto", 14),
                                               command=lambda: self.close_modal(modal))
        modal_button.grid(row=3, column=0, stick="ews", padx=20, pady=(0, 20))

    def choose_color(self, choice):
        if choice == "Green":
            customtkinter.set_default_color_theme("green")
            self.default_color = "#2fa572"
            self.default_background_dark = "#2b2b2b"
            self.default_background_light = "#dbdbdb"
        elif choice == "Blue":
            customtkinter.set_default_color_theme("blue")
            self.default_color = "#1f6aa5"
            self.default_background_dark = "#2b2b2b"
            self.default_background_light = "#dbdbdb"
        else:
            customtkinter.set_default_color_theme("dark-blue")
            self.default_color = "#1f538d"
            self.default_background_dark = "#212121"
            self.default_background_light = "#e5e5e5"
        self.refresh()

    def refresh(self):
        if self.loaded_frame == "keys":
            self.frame_keys = self.load_frame_keys(self.frame_keys)
        elif self.loaded_frame == "send":
            self.frame_send = self.load_frame_send(self.frame_send)
        else:
            self.frame_receive = self.load_frame_receive(self.frame_receive)


if __name__ == "__main__":
    app = PGP_App()
    app.mainloop()
