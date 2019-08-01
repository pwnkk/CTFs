from PIL import Image
import libnum
res = ""
for i in range(104):
    im = Image.open("gif/"+str(i)+".jpg")
    if im.getcolors()[0][1][0]==255:
        res+="0"
    if im.getcolors()[0][1][0]==12:
        res+="1"

num = int(res,2)
print libnum.n2s(num)

