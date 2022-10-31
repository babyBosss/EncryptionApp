# from kivy.config import Config
from kivy.config import Config
Config.set('input', 'mouse', 'mouse,multitouch_on_demand')

Config.set('graphics', 'resizable', False)

from kivy.uix.image import Image
from kivy.app import App
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
# from  kivy.uix.filechooser import FileChooserListView
from kivy.core.window import Window
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


Window.size = (730, 480)
Window.clearcolor = (1, 1, 1, 1)

key = Fernet.generate_key()


class CryptApp(App):
    side = False
    wayto_var = ""
    wayfrom_var = ""
    filename = ""
    message = ""
    savefile = ""
    decrypted = ""

    def _on_file_drop(self, window, file_path):
        self.way_from_textinput.text = file_path
        self.way_to_textinput.text = ""
        self.l5.text = "Choose what to do with the file"
        return

    def enc_btn_press(self, instance):

        self.wayfrom_var = self.way_from_textinput.text
        self.wayto_var = self.way_to_textinput.text

        # ШИФРОВАНИЕ ТЕКСТА
        if self.side == True:
            self.message = self.textInput.text

        # ШИФРОВАНИЕ ФАЙЛА
        else:
            try:
                with open(self.wayfrom_var, mode='rb') as file:
                    self.message = file.read()
                    # print("файл from открыт")
            except:
                self.l5.text = "An IOError has occurred!"

            if self.wayto_var == "":
                self.wayto_var = self.wayfrom_var + ".enc"
                if self.way_from_textinput.text != "":
                    self.way_to_textinput.text = self.wayto_var
            try:
                self.savefile = open(self.wayto_var, 'wb')
                self.l5.text = "Encryption succeeded, file saved. Don't forget to save your password"
            except:
                self.l5.text = "An IOError has occurred!"


        password_provided = self.pass_textinput.text

        password = password_provided.encode()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
        f = Fernet(key)

        if type(self.message) != bytes:
            encrypted = f.encrypt(self.message.encode())
        else:
            encrypted = f.encrypt(self.message)

        #сохранение результатов
        if self.side == True:
            if self.message != "":
                self.textOutput.text = encrypted
                self.l5.text = "Encryption succeeded. Remember to save your password"
            else:
                self.textOutput.text = ""
        else:
            with open(self.wayto_var, mode='wb') as savefile:
                savefile.write(encrypted)
        if self.message != "":
            self.pass_textinput.text = key
        else:
            self.pass_textinput.text = ""


    def dec_btn_press(self, instance):
        self.wayfrom_var = self.way_from_textinput.text
        self.wayto_var = self.way_to_textinput.text


        key = self.pass_textinput.text


        # ДЕШИФРОВАНИЕ ТЕКСТА
        if self.side == True:
            self.message = self.textInput.text

            if(self.message != "" and key != ""):

                if type(self.message) != bytes:
                    try:
                        f = Fernet(key.encode())
                        self.decrypted = f.decrypt(self.message.encode())
                    except:
                        self.l5.text = "Decryption failed"
                else:
                    try:
                        f = Fernet(key.encode())
                        self.decrypted = f.decrypt(self.message.encode())
                    except:
                        self.l5.text = "Decryption failed"
                self.textOutput.text = self.decrypted
            else:
                if self.message == "":
                    self.l5.text = "Enter your message"


        # ДЕШИФРОВАНИЕ ФАЙЛА
        else:
            try:
                with open(self.wayfrom_var, mode='rb') as file:
                    self.message = file.read()
            except:
                self.l5.text = "An IOError has occurred!"

            if self.wayfrom_var.endswith(".enc") and self.way_to_textinput.text == "":
                self.wayto_var = self.wayfrom_var.replace(".enc", "")
                # print(self.wayto_var)
            #
            # while (os.path.isfile(self.wayto_var + ".enc")):
            #     self.wayto_var = self.wayto_var + ???
            #

            try:
                f = Fernet(key.encode())
                if type(self.message) != bytes:
                    self.decrypted = f.decrypt(self.message.encode())
                else:
                    self.decrypted = f.decrypt(self.message)
                # self.decrypted = f.decrypt(self.message)

                with open(self.wayto_var, mode='wb') as savefile:
                    savefile.write(self.decrypted)
                self.way_to_textinput.text = self.wayto_var
            except:
                self.l5.text = "Decryption failed"

    # def _fbrowser_canceled(self, instance):
    #     print('cancelled, Close self.')
    #
    # def _fbrowser_success(self, instance):
    #     print (instance.selection)

    def wayfrom_btn_press(self, instance):
        # self.wayfrom_var = filedialog.askopenfilename()
        # self.textInput.text = self.way_from_textinput.text
        # self.wayfrom_var = self.way_from_textinput.text

        print(self.wayfrom_var)

    def wayto_btn_press(self, instance):
        # self.textInput.text = self.way_to_textinput.text
        # self.wayto_var = self.way_to_textinput.text
        print(self.wayto_var)

    def left_btn_press(self, instance):
        if self.side == True:
            self.left_button.background_color=[1,255,1,255]
            self.left_button.color=[255,255,255,1]
            self.right_button.background_color = [.26, .18, .99, 1]
            self.right_button.color = [1,1,1,1]
        self.side = False

    def right_btn_press(self, instance):
        if self.side == False:
            self.right_button.background_color = [1, 255, 1, 255]
            self.right_button.color = [255, 255, 255, 1]
            self.left_button.background_color = [.26, .18, .99, 1]
            self.left_button.color = [1, 1, 1, 1]
        self.side = True




    def build(self):

        Window.bind(on_dropfile=self._on_file_drop)

        self.title = 'Cryptographer'

        layout = FloatLayout()

        enc_button = Button(
            text="ENCRYPT",
            font_size=50,
            background_color=[.26, .18, .90, .90],
            on_press=self.enc_btn_press,
            size_hint=(None, None),
            height=200,
            width=300,
            pos=(830, 30))

        dec_button = Button(
            text="DECRYPT",
            font_size=50,
            background_color=[.26, .18, .90, .90],
            on_press=self.dec_btn_press,
            size_hint=(None, None),
            height=200,
            width=300,
            pos=(1130, 30))

        way_to_button = Button(
            text="select",
            font_size=20,
            background_color=[.26, .18, .90, .85],
            on_press=self.wayto_btn_press,
            size_hint=(None, None),
            height=70,
            width=80,
            pos=(550, 490))

        way_from_button = Button(
            text="select",
            font_size=20,

            background_color=[.26, .18, .90, .85],
            on_press=self.wayfrom_btn_press,
            size_hint=(None, None),
            height=70,
            width=80,
            pos=(550, 590))

        self.right_button = Button(
            text="->",
            font_size=40,
            background_color=[.26, .18, .90, .85],
            on_press=self.right_btn_press,
            size_hint=(None, None),
            height=170,
            width=100,
            pos=(729, 490))

        self.left_button = Button(
            text="<-",
            font_size=40,
            background_color=[.26, .18, .90, .85],
            on_press=self.left_btn_press,
            size_hint=(None, None),
            height=170,
            width=100,
            pos=(630, 490))

        self.pass_textinput = TextInput(font_size=30,
                                        background_color=(10, 5, 100, 100),
                                        text="",
                                        multiline=True,
                                        pos=(30, 280),
                                        height=160,
                                        width=600,
                                        size_hint=(None, None))

        self.way_from_textinput = TextInput(
                                            font_size=30,
                                            background_color=(10, 5, 100, 100),
                                            # halign="right",
                                            text="",
                                            multiline=False,
                                            pos=(30, 590),
                                            height=70,
                                            width=520,
                                            size_hint=(None, None))

        self.way_to_textinput = TextInput(
            font_size=30,
                                          background_color=(10, 5, 100, 100),
                                          #halign="right",
                                          text="",
                                          multiline=False,
                                          pos=(30, 490),
                                          height=70,
                                          width=520,
                                          size_hint=(None, None))

        self.textInput = TextInput(
                            font_size=30,
                            background_color=(10, 5, 100, 100),
                            text="",
                            multiline=True,
                            pos=(830, 490),
                            height=170,
                            width=600,
                            size_hint=(None, None))

        self.textOutput = TextInput(
                            font_size=30,
                            background_color=(10, 5, 100, 100),
                            text="",
                            multiline=True,
                            pos=(830, 280),
                            height=160,
                            width=600,
                            size_hint=(None, None))

        image = Image(source='icon1.png',
                     size_hint=(.5,.5),
                     height=800,
                     width=820,
                     # height=600,
                     # width=720,
                     pos=(400, 583))

        self.l1 = Label(text="Input file",
                        font_size=30,
                        size_hint=(None, None),
                        color=(255,255,255,1),
                        height= 1350,
                        width=185,
                        halign="center",
                        valign="middle")

        self.l2 = Label(text="Output file",
                        font_size=30,
                        size_hint=(None, None),
                        color=(255, 255, 255, 1),
                        height=1149,
                        width=200,
                        halign="left",
                        valign="middle")

        l3 = Label(text="Password",
                   font_size=30,
                   size_hint=(None, None),
                   color=(255, 255, 255, 1),
                   pos=(50, 408),
                   halign="left",
                   valign="middle")
        l4 = Label(text="Enter text here",
                   font_size=30,
                   size_hint=(None, None),
                   color=(255, 255, 255, 1),
                   pos=(880, 625),
                   halign="left",
                   valign="middle")

        l6 = Label(text="Featured text here",
                   font_size=30,
                   size_hint=(None, None),
                   color=(255, 255, 255, 1),
                   pos=(900, 408),
                   halign="left",
                   valign="middle")


        self.l5 = TextInput(font_size=30,
                            background_color=(0,0,0,0),
                            readonly=True,
                            text="You can specify a file or enter text for encryption or decryption",
                            multiline=True,
                            pos=(30, 30),
                            height=200,
                            width=600,
                            size_hint=(None, None))

        self.left_button.background_color = [1, 255, 1, 255]
        self.left_button.color = [255, 255, 255, 1]
        layout.add_widget(self.way_from_textinput)
        layout.add_widget(self.way_to_textinput)
        layout.add_widget(self.textInput)
        layout.add_widget(self.textOutput)
        layout.add_widget(self.pass_textinput)
        layout.add_widget(enc_button)
        layout.add_widget(dec_button)
        layout.add_widget(way_to_button)
        layout.add_widget(way_from_button)
        layout.add_widget(self.l1)
        layout.add_widget(self.l2)
        layout.add_widget(l3)
        layout.add_widget(l4)
        layout.add_widget(self.l5)
        layout.add_widget(l6)
        layout.add_widget(self.left_button)
        layout.add_widget(self.right_button)
        layout.add_widget(image)

        return layout


if __name__ == "__main__":
    CryptApp().run()
