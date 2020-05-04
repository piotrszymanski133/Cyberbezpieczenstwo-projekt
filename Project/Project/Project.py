import kivy
from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.config import Config
from kivy.uix.dropdown import DropDown

import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes



class MyApp(App):

    def build(self):
        Config.set('graphics', 'width', '900')
        Config.set('graphics', 'height', '300')
        Config.write()
        self.box = BoxLayout(orientation='horizontal', spacing=10)
        self.button_box = BoxLayout(orientation = 'vertical',pos_hint = {'top':1}, spacing=10, size_hint=(0.2,0.4))
        self.plain_text = TextInput(hint_text='Wpisz tekst do zaszyfrowania',  pos_hint = {'top':1}, size_hint=(.5,.4))
        self.cipher_text = TextInput(hint_text='Wpisz tekst do odszyfrowania',  pos_hint = {'top':1}, size_hint=(.5,.4))
        self.dropdown = DropDown()
        btn = Button(text = 'CBC', size_hint_y=None, height = 35)
        btn.bind(on_release=lambda btn: self.dropdown.select(btn.text))
        self.dropdown.add_widget(btn)
        btn = Button(text = 'ECB', size_hint_y=None, height = 35)
        btn.bind(on_release=lambda btn: self.dropdown.select(btn.text))
        self.dropdown.add_widget(btn)
        btn = Button(text = 'CTR', size_hint_y=None, height = 35)
        btn.bind(on_release=lambda btn: self.dropdown.select(btn.text))
        self.drop_down_button = Button(text='Tryb', size_hint=(1, .5))
        self.drop_down_button.bind(on_release=self.dropdown.open)
        self.dropdown.bind(on_select=lambda instance, x: setattr(self.drop_down_button, 'text', x))
        self.dropdown.add_widget(btn)
        self.code_button = Button(text='Koduj', pos_hint = {'top':1}, on_press=self.code, size_hint=(1,.5))
        self.decode_button = Button(text='Dekoduj',  pos_hint = {'top':1}, on_press=self.decode, size_hint=(1,.5))
        self.box.add_widget(self.plain_text)
        self.button_box.add_widget(self.code_button)
        self.button_box.add_widget(self.decode_button)
        self.button_box.add_widget(self.drop_down_button)
        self.box.add_widget(self.button_box)
        self.box.add_widget(self.cipher_text)
        return self.box

    def code(self, instance):
        if self.drop_down_button.text == 'CBC':
            self.cipher_text.text = ''.join(reversed(self.plain_text.text))
        else:
            self.cipher_text.text = 'cjuh'

    def decode(self, instance):
        if self.drop_down_button.text == 'CBC':
            self.plain_text.text = ''.join(reversed(self.cipher_text.text))
        else:
            self.plain_text.text = 'hjuc'


if __name__ == "__main__":
    data = b"secret"
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(data)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'nonce':nonce, 'ciphertext':ct})
    print(result)
    MyApp().run()