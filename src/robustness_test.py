import correctness_test as correctness_test
import shutil

inputs = ["Test!",
         "ÆØÅ",
         123,
         " ",
         "",
         "/()=?`´^!<>|,.;:-_'",
         None,
         "äöüß§$%&",
         "Привет, мир!",
         "你好世界",
         "مرحبا بالعالم!",
         "½",
         "\0",
         '''
         one line
         two lines
         three lines
         ''',
         "multi\nline\n",
         "t\ta\tb",
         "🌊🐙🚢🐟🌊🐠🛥️🌊🦈",
         "." * 3000,
         ]


for input in inputs:
    correctness_test.correctness_test(input)

shutil.rmtree("keys/")