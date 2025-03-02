#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# !cd C:\Users\ASUS\Downloads\Malware-classification


# Before running this notebook, make sure to download the dataset first. The dataset used here is of Microsoft Malware Classification Challenge(2015), can be found in kaggle: https://www.kaggle.com/competitions/malware-classification

# In[2]:


import warnings
warnings.filterwarnings("ignore")
import shutil
import os
import pandas as pd
import matplotlib
matplotlib.use(u'nbAgg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pickle
from sklearn.manifold import TSNE
from sklearn import preprocessing
import pandas as pd
from multiprocessing import Process# this is used for multithreading
import multiprocessing
import codecs# this is used for file operations 
import random as r
from xgboost import XGBClassifier
from sklearn.model_selection import RandomizedSearchCV
from sklearn.tree import DecisionTreeClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import log_loss
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier


# In[3]:


source = 'Train'
destination = 'byteFiles'

if not os.path.isdir(destination):
    os.makedirs(destination)

if os.path.isdir(source):
    os.rename(source,'asmFiles')


# In[4]:


# aggregate both asm and byte files into their respective folders
source='asmFiles'
data_files = os.listdir(source)
for file in data_files:
    if (file.endswith("bytes")):
        shutil.move(source+'\\'+file,destination)


# ## File size of Byte Files as a feature 

# In[5]:


Y=pd.read_csv("trainLabels.csv")
files=os.listdir('byteFiles')
filenames=Y['Id'].tolist()
Malware=1
class_y=Y['Class'].tolist()
class_bytes=[]
sizebytes=[]
fnames=[]
for file in files:
    # create file beforehand on the directory, can use above cmd changing name of file
    statinfo=os.stat('byteFiles/'+file)
    # split the file name at '.' and take the first part of it i.e the file name
    file=file.split('.')[0]
    if any(file == filename for filename in filenames):
        i=filenames.index(file)
        class_bytes.append(class_y[i])
        # converting into Mb's
        sizebytes.append(statinfo.st_size/(1024.0*1024.0))
        fnames.append(file)
data_size_byte=pd.DataFrame({'ID':fnames,'size':sizebytes,'Class':class_bytes,'Malware':Malware})
print (data_size_byte.head())


# ## Feature Extraction from Byte Files

# In[10]:


#removal of addres from byte files
# contents of .byte files
# ----------------
#00401000 56 8D 44 24 08 50 8B F1 E8 1C 1B 00 00 C7 06 08 
#-------------------
#we remove the starting address 00401000

files = os.listdir('byteFiles')
filenames=[]
array=[]
for file in files:
    if(file.endswith("bytes")):
        file=file.split('.')[0]
        text_file = open('byteFiles_txt/'+file+".txt", 'w+')
        file = file+'.bytes'
        with open('byteFiles/'+file,"r") as fp:
            lines=""
            for line in fp:
                a=line.rstrip().split(" ")[1:]
                b=' '.join(a)
                b=b+"\n"
                text_file.write(b)
            fp.close()
            #os.remove('byteFiles/'+file)
        text_file.close()


# In[11]:


files = os.listdir('byteFiles_txt')
filenames2=[]
feature_matrix = np.zeros((len(files),257),dtype=int)
k=0
byte_feature_file=open('byteFiles.csv','w+')
byte_feature_file.write("ID,0,1,2,3,4,5,6,7,8,9,0a,0b,0c,0d,0e,0f,10,11,12,13,14,15,16,17,18,19,1a,1b,1c,1d,1e,1f,20,21,22,23,24,25,26,27,28,29,2a,2b,2c,2d,2e,2f,30,31,32,33,34,35,36,37,38,39,3a,3b,3c,3d,3e,3f,40,41,42,43,44,45,46,47,48,49,4a,4b,4c,4d,4e,4f,50,51,52,53,54,55,56,57,58,59,5a,5b,5c,5d,5e,5f,60,61,62,63,64,65,66,67,68,69,6a,6b,6c,6d,6e,6f,70,71,72,73,74,75,76,77,78,79,7a,7b,7c,7d,7e,7f,80,81,82,83,84,85,86,87,88,89,8a,8b,8c,8d,8e,8f,90,91,92,93,94,95,96,97,98,99,9a,9b,9c,9d,9e,9f,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af,b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf,d0,d1,d2,d3,d4,d5,d6,d7,d8,d9,da,db,dc,dd,de,df,e0,e1,e2,e3,e4,e5,e6,e7,e8,e9,ea,eb,ec,ed,ee,ef,f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,fa,fb,fc,fd,fe,ff,??,")
byte_feature_file.write("\n")
for file in files:
    filenames2.append(file)
    byte_feature_file.write(file.split('.')[0]+",")
    if(file.endswith("txt")):
        with open('byteFiles_txt/'+file,"r") as byte_file:
            for lines in byte_file:
                line=lines.rstrip().split(" ")
                for hex_code in line:
                    if hex_code=='??':
                        feature_matrix[k][256]+=1
                    else:
                        feature_matrix[k][int(hex_code,16)]+=1
        byte_file.close()
    for i in feature_matrix[k]:
        byte_feature_file.write(str(i)+",")
    byte_feature_file.write("\n")
    
    k += 1

byte_feature_file.close()


# In[ ]:


#For single file
'''
f_m = np.zeros((1,257),dtype=int)
f='0A32eTdBKayjCWhZqDOQ.txt'
b_f_f=open('r.csv','w+')
b_f_f.write("ID,0,1,2,3,4,5,6,7,8,9,0a,0b,0c,0d,0e,0f,10,11,12,13,14,15,16,17,18,19,1a,1b,1c,1d,1e,1f,20,21,22,23,24,25,26,27,28,29,2a,2b,2c,2d,2e,2f,30,31,32,33,34,35,36,37,38,39,3a,3b,3c,3d,3e,3f,40,41,42,43,44,45,46,47,48,49,4a,4b,4c,4d,4e,4f,50,51,52,53,54,55,56,57,58,59,5a,5b,5c,5d,5e,5f,60,61,62,63,64,65,66,67,68,69,6a,6b,6c,6d,6e,6f,70,71,72,73,74,75,76,77,78,79,7a,7b,7c,7d,7e,7f,80,81,82,83,84,85,86,87,88,89,8a,8b,8c,8d,8e,8f,90,91,92,93,94,95,96,97,98,99,9a,9b,9c,9d,9e,9f,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af,b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf,d0,d1,d2,d3,d4,d5,d6,d7,d8,d9,da,db,dc,dd,de,df,e0,e1,e2,e3,e4,e5,e6,e7,e8,e9,ea,eb,ec,ed,ee,ef,f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,fa,fb,fc,fd,fe,ff,??,")
b_f_f.write('\n')
b_f_f.write(file.split('.')[0]+",")
if(f.endswith("txt")):
    with open('byteFiles_txt/'+f,"r") as b_f:
        for lines in b_f:
            line=lines.rstrip().split(" ")
            for hex_code in line:
                if hex_code=='??':
                    f_m[0][256]+=1
                else:
                    f_m[0][int(hex_code,16)]+=1
    b_f.close()
for i in f_m[0]:
    b_f_f.write(str(i)+",")
b_f_f.write("\n")
b_f_f.close()
bf=pd.read_csv("r.csv")
bf
'''


# In[13]:


byte_features=pd.read_csv("byteFiles.csv")
result=byte_features.drop(columns=['Unnamed: 258'])
result


# In[14]:


def normalize(df):
    result1 = df.copy()
    for feature_name in df.columns:
        if (str(feature_name) != str('ID') and str(feature_name)!=str('Class')):
            max_value = df[feature_name].max()
            min_value = df[feature_name].min()
            result1[feature_name] = (df[feature_name] - min_value) / (max_value - min_value)
    return result1
result = normalize(result)


# In[18]:


result_byte = pd.merge(byte_features.drop(columns=['Unnamed: 258']), data_size_byte,on='ID', how='left')
result_byte.head()


# In[19]:


import joblib
joblib.dump(result_byte, 'pkl/result_byte.pkl') #Create a file with name pkl(to store pickles)


# In[ ]:





# ## Feature Extraction from ASM Files

# In[20]:


def asmprocess():
    #The prefixes tells about the segments that are present in the asm files
    #There are 450 segments(approx) present in all asm files
    prefixes = ['HEADER:','.text:','.Pav:','.idata:','.data:','.bss:','.rdata:','.edata:','.rsrc:','.tls:','.reloc:','.BSS:','.CODE']
    opcodes = ['jmp', 'mov', 'retf', 'push', 'pop', 'xor', 'retn', 'nop', 'sub', 'inc', 'dec', 'add','imul', 'xchg', 'or', 'shr', 'cmp', 'call', 'shl', 'ror', 'rol', 'jnb','jz','rtn','lea','movzx']
    keywords = ['.dll','std::',':dword']
    # general purpose registers and special registers 
    registers=['edx','esi','eax','ebx','ecx','edi','ebp','esp','eip']
    file1=open("asmfiles.csv","w+")
    file1.write('ID,'+','.join(ele for ele in (prefixes + opcodes + keywords + registers))+','+'\n')
    files = os.listdir('asmFiles')
    for f in files:
        prefixescount=np.zeros(len(prefixes),dtype=int)
        opcodescount=np.zeros(len(opcodes),dtype=int)
        keywordcount=np.zeros(len(keywords),dtype=int)
        registerscount=np.zeros(len(registers),dtype=int)
        features=[]
        f2=f.split('.')[0]
        file1.write(f2+",")

        # https://docs.python.org/3/library/codecs.html#codecs.ignore_errors
        # https://docs.python.org/3/library/codecs.html#codecs.Codec.encode
        with codecs.open('asmFiles/'+f,encoding='cp1252',errors ='replace') as fli:
            for lines in fli:
                line=lines.rstrip().split()
                l=line[0]
                
                for i in range(len(prefixes)):
                    if prefixes[i] in line[0]:
                        prefixescount[i]+=1
                line=line[1:]

                for i in range(len(opcodes)):
                    if any(opcodes[i]==li for li in line):
                        features.append(opcodes[i])
                        opcodescount[i]+=1
 
                for i in range(len(registers)):
                    for li in line:
                        # we will use registers only in 'text' and 'CODE' segments
                        if registers[i] in li and ('text' in l or 'CODE' in l):
                            registerscount[i]+=1
                
                for i in range(len(keywords)):
                    for li in line:
                        if keywords[i] in li:
                            keywordcount[i]+=1
        
        for prefix in prefixescount:
            file1.write(str(prefix)+",")
        for opcode in opcodescount:
            file1.write(str(opcode)+",")
        for register in registerscount:
            file1.write(str(register)+",")
        for key in keywordcount:
            file1.write(str(key)+",")
        file1.write("\n")
    file1.close()
    
def main():
    manager=multiprocessing.Manager()
    p1=Process(target=asmprocess())
    p1.start()
    p1.join()
    
if __name__=="__main__":
    main()    


# In[21]:


dfasm=pd.read_csv("asmfiles.csv")
df_asm=dfasm.drop(columns=['Unnamed: 52'])
df_asm


# ## File size of ASM Files as a feature

# In[22]:


files=os.listdir('asmFiles')
filenames=Y['Id'].tolist()
Malware=1
class_y=Y['Class'].tolist()
class_bytes=[]
sizebytes=[]
fnames=[]
for file in files:
    statinfo=os.stat('asmFiles/'+file)
    file=file.split('.')[0]
    if any(file == filename for filename in filenames):
        i=filenames.index(file)
        class_bytes.append(class_y[i])
        # converting into Mb's
        sizebytes.append(statinfo.st_size/(1024.0*1024.0))
        fnames.append(file)
asm_size_byte=pd.DataFrame({'ID':fnames,'size':sizebytes,'Class':class_bytes,'Malware':Malware})
print (asm_size_byte.head())


# In[23]:


print(df_asm.shape)
print(asm_size_byte.shape)
result_asm = pd.merge(df_asm, asm_size_byte, on='ID', how='left')
result_asm.head()


# In[ ]:





# ## Merging Byte and Asm file features

# In[24]:


result_x = pd.merge(result_byte,result_asm.drop(['Class','Malware'], axis=1),on='ID', how='left')
result_y = result_x['Class']
result_x = result_x.drop(['ID','rtn','.BSS:','.CODE','Class'], axis=1)
result_x.head()


# In[25]:


result_x.to_csv(r'merged.csv')


# ## Byte N-grams(2,3 grams)

# In[26]:


result_x['ID'] = result.ID


# In[27]:


byte_vocab = "00,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d,0e,0f,10,11,12,13,14,15,16,17,18,19,1a,1b,1c,1d,1e,1f,20,21,22,23,24,25,26,27,28,29,2a,2b,2c,2d,2e,2f,30,31,32,33,34,35,36,37,38,39,3a,3b,3c,3d,3e,3f,40,41,42,43,44,45,46,47,48,49,4a,4b,4c,4d,4e,4f,50,51,52,53,54,55,56,57,58,59,5a,5b,5c,5d,5e,5f,60,61,62,63,64,65,66,67,68,69,6a,6b,6c,6d,6e,6f,70,71,72,73,74,75,76,77,78,79,7a,7b,7c,7d,7e,7f,80,81,82,83,84,85,86,87,88,89,8a,8b,8c,8d,8e,8f,90,91,92,93,94,95,96,97,98,99,9a,9b,9c,9d,9e,9f,a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af,b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf,d0,d1,d2,d3,d4,d5,d6,d7,d8,d9,da,db,dc,dd,de,df,e0,e1,e2,e3,e4,e5,e6,e7,e8,e9,ea,eb,ec,ed,ee,ef,f0,f1,f2,f3,f4,f5,f6,f7,f8,f9,fa,fb,fc,fd,fe,ff,??"


# In[28]:


def byte_bigram():    
    byte_bigram_vocab = []
    for i, v in enumerate(byte_vocab.split(',')):
        for j in range(0, len(byte_vocab.split(','))):
            byte_bigram_vocab.append(v + ' ' +byte_vocab.split(',')[j])
    return byte_bigram_vocab


# In[29]:


byte_bigram()


# In[30]:


len(byte_bigram())


# In[31]:


def byte_trigram():
    byte_trigram_vocab = []
    for i, v in enumerate(byte_vocab.split(',')):
        for j in range(0, len(byte_vocab.split(','))):
            for k in range(0, len(byte_vocab.split(','))):
                byte_trigram_vocab.append(v + ' ' +byte_vocab.split(',')[j]+' '+byte_vocab.split(',')[k])
    return byte_trigram_vocab


# In[32]:


byte_trigram()


# In[33]:


from tqdm import tqdm 
from sklearn.feature_extraction.text import CountVectorizer
import scipy


# In[34]:


vector = CountVectorizer(lowercase=False,ngram_range=(2,2), vocabulary=byte_bigram())
bytebigram_vect = scipy.sparse.csr_matrix((1000, 66049))#(len(byte_bigram_vocab)=66049 and 1000 byte files)
for i, file in tqdm(enumerate(os.listdir('byteFiles_txt'))):
    f = open('byteFiles_txt/' + file)
    bytebigram_vect[i,:]+= scipy.sparse.csr_matrix(vector.fit_transform([f.read().replace('\n', ' ').lower()]))
    f.close()


# In[35]:


bytebigram_vect


# In[36]:


scipy.sparse.save_npz('bytebigram.npz', bytebigram_vect)


# In[37]:


from sklearn.preprocessing import normalize
byte_bigram_vect = normalize(scipy.sparse.load_npz('bytebigram.npz'), axis = 0)


# ## Opcode N-grams(2,3,4 grams)

# In[38]:


opcodes = ['jmp', 'mov', 'retf', 'push', 'pop', 'xor', 'retn', 'nop', 'sub', 'inc', 'dec', 'add','imul', 'xchg', 'or', 'shr', 'cmp', 'call', 'shl', 'ror', 'rol', 'jnb','jz','rtn','lea','movzx']


# In[39]:


def asmopcodebigram():
    asmopcodebigram = []
    for i, v in enumerate(opcodes):
        for j in range(0, len(opcodes)):
            asmopcodebigram.append(v + ' ' + opcodes[j])
    return asmopcodebigram


# In[40]:


asmopcodebigram()


# In[41]:


def asmopcodetrigram():
    asmopcodetrigram = []
    for i, v in enumerate(opcodes):
        for j in range(0, len(opcodes)):
            for k in range(0, len(opcodes)):
                asmopcodetrigram.append(v + ' ' + opcodes[j] + ' ' + opcodes[k])
    return asmopcodetrigram


# In[42]:


asmopcodetrigram()


# In[43]:


def asmopcodetetragram():
    asmopcodetetragram = []
    for i, v in enumerate(opcodes):
        for j in range(0, len(opcodes)):
            for k in range(0, len(opcodes)):
                for l in range(0, len(opcodes)):
                    asmopcodetetragram.append(v + ' ' + opcodes[j] + ' ' + opcodes[k] + ' ' + opcodes[l])
    return asmopcodetetragram


# In[44]:


asmopcodetetragram()


# In[45]:


def opcode_collect():
    op_file = open("opcode_file.txt", "w+")
    for asmfile in os.listdir('asmFiles'):
        opcode_str = ""
        with codecs.open('asmFiles/' + asmfile, encoding='cp1252', errors ='replace') as file:
            for lines in file:
                line = lines.rstrip().split()            
                for li in line:
                    if li in opcodes:
                        opcode_str += li + ' '
        op_file.write(opcode_str + "\n")
    op_file.close()
opcode_collect()


# In[47]:


vect = CountVectorizer(ngram_range=(2, 2), vocabulary = asmopcodebigram())
opcodebivect = scipy.sparse.csr_matrix((1000, len(asmopcodebigram()))) # 10,868 ASM files
raw_opcode = open('opcode_file.txt').read().split('\n')

for indx in range(1000):
    opcodebivect[indx, :] += scipy.sparse.csr_matrix(vect.transform([raw_opcode[indx]]))


# In[48]:


opcodebivect


# In[49]:


scipy.sparse.save_npz('opcodebigram.npz', opcodebivect)


# In[50]:


vect = CountVectorizer(ngram_range=(3, 3), vocabulary = asmopcodetrigram())
opcodetrivect = scipy.sparse.csr_matrix((1000, len(asmopcodetrigram())))

for indx in range(1000):
    opcodetrivect[indx, :] += scipy.sparse.csr_matrix(vect.transform([raw_opcode[indx]]))


# In[51]:


opcodetrivect


# In[52]:


scipy.sparse.save_npz('opcodetrigram.npz', opcodetrivect)


# In[53]:


vect = CountVectorizer(ngram_range=(4, 4), vocabulary = asmopcodetetragram())
opcodetetravect = scipy.sparse.csr_matrix((1000, len(asmopcodetetragram())))

for indx in range(1000):
    opcodetetravect[indx, :] += scipy.sparse.csr_matrix(vect.transform([raw_opcode[indx]]))


# In[54]:


opcodetetravect


# In[55]:


scipy.sparse.save_npz('opcodetetragram.npz', opcodetetravect)


# In[56]:


opcodebivect    = scipy.sparse.load_npz('opcodebigram.npz')
opcodetrivect   = scipy.sparse.load_npz('opcodetrigram.npz')
opcodetetravect = scipy.sparse.load_npz('opcodetetragram.npz')


# ## Image Feature Extraction from ASM Files

# In[57]:


import array
import imageio


# In[60]:


def collect_img_asm():
    for asmfile in os.listdir("asmFiles"):
        filename = asmfile.split('.')[0]
        file = codecs.open("asmFiles/" + asmfile, 'rb')
        filelen = os.path.getsize("asmFiles/" + asmfile)
        width = int(filelen ** 0.5)
        rem = int(filelen / width)
        arr = array.array('B')
        arr.frombytes(file.read())
        file.close()
        reshaped = np.reshape(arr[:width * width], (width, width))
        reshaped = np.uint8(reshaped)
        #scipy.misc.imsave('asm_image/' + filename + '.png',reshaped)
        imageio.imwrite('asm_image/' + filename + '.png',reshaped)


# In[61]:


collect_img_asm()


# In[63]:


from IPython.display import Image 
Image(filename='asm_image/0cfIE39ihRNo2rkZOw5H.png')


# ## First 200 Image Pixels

# In[64]:


import cv2
imagefeatures = np.zeros((1000, 200)) # 10,868 files


# In[65]:


for i, asmfile in enumerate(os.listdir("asmFiles")):
    img = cv2.imread("asm_image/" + asmfile.split('.')[0] + '.png')
    img_arr = img.flatten()[:200]
    imagefeatures[i, :] += img_arr


# In[66]:


img_features_name = []
for i in range(200):
    img_features_name.append('pix' + str(i))
imgdf = pd.DataFrame(normalize(imagefeatures, axis = 0), columns = img_features_name)


# In[67]:


imgdf['ID'] = result.ID


# In[68]:


imgdf.head()


# In[69]:


#import joblib
joblib.dump(imgdf, 'img_df')


# In[70]:


img_df=joblib.load('img_df')


# In[71]:


img_df.head()


# In[ ]:





# ## Important Feature Selection Using Random Forest

# In[30]:


def imp_features(data, features, keep):
    rf = RandomForestClassifier(n_estimators = 100, n_jobs = -1)
    rf.fit(data, result_y)
    imp_feature_indx = np.argsort(rf.feature_importances_)[::-1]
    imp_value = np.take(rf.feature_importances_, imp_feature_indx[:20])
    imp_feature_name = np.take(features, imp_feature_indx[:20])
    sns.set()
    plt.figure(figsize = (10, 5))
    ax = sns.barplot(x = imp_feature_name, y = imp_value)
    ax.set_xticklabels(labels = imp_feature_name, rotation = 45)
    sns.set_palette(reversed(sns.color_palette("husl", 10)), 10)
    plt.title('Important Features')
    plt.xlabel('Feature Names')
    plt.ylabel('Importance')
    return imp_feature_indx[:keep]


# ## Important Features Among Opcode Bi-Gram

# In[91]:


op_bi_indxes = imp_features(normalize(opcodebivect, axis = 0), asmopcodebigram(), 200)


# In[97]:


op_bi_df = pd.DataFrame.sparse.from_spmatrix(normalize(opcodebivect, axis = 0), columns = asmopcodebigram())
for col in op_bi_df.columns:
    if col not in np.take(asmopcodebigram(), op_bi_indxes):
        op_bi_df.drop(col, axis = 1, inplace = True)


# In[99]:


op_bi_df.sparse.to_dense().to_csv('op_bi.csv')


# In[100]:


op_bi_df = pd.read_csv('op_bi.csv').drop('Unnamed: 0', axis = 1).fillna(0)


# In[101]:


op_bi_df['ID'] = result.ID
op_bi_df.head()


# ## Important Features Among Opcode Tri-Gram

# In[102]:


op_tri_indxes = imp_features(normalize(opcodetrivect, axis = 0), asmopcodetrigram(), 200)


# In[103]:


op_tri_df = pd.DataFrame.sparse.from_spmatrix(normalize(opcodetrivect, axis = 0), columns = asmopcodetrigram())
op_tri_df = op_tri_df.loc[:, np.intersect1d(op_tri_df.columns, np.take(asmopcodetrigram(), op_tri_indxes))]


# In[105]:


op_tri_df.sparse.to_dense().to_csv('op_tri.csv')
op_tri_df = pd.read_csv('op_tri.csv').drop('Unnamed: 0', axis = 1).fillna(0)
op_tri_df['ID'] = result.ID
op_tri_df.head()


# ## Important Features Among Opcode Tetra-Gram

# In[108]:


op_tetra_indxes = imp_features(normalize(opcodetetravect, axis = 0), asmopcodetetragram(), 200)


# In[109]:


op_tetra_df = pd.DataFrame.sparse.from_spmatrix(normalize(opcodetetravect, axis = 0), columns = asmopcodetetragram())
op_tetra_df = op_tetra_df.loc[:, np.intersect1d(op_tetra_df.columns, np.take(asmopcodetetragram(), op_tetra_indxes))]


# In[110]:


op_tetra_df.sparse.to_dense().to_csv('op_tetra.csv')
op_tetra_df = pd.read_csv('op_tetra.csv').drop('Unnamed: 0', axis = 1).fillna(0)
op_tetra_df['ID'] = result.ID
op_tetra_df.head()


# ## Important Features Among Byte Bi-Gram

# In[39]:


byte_bi_indxes = imp_features(normalize(byte_bigram_vect, axis = 0), byte_bigram(), 400)


# In[ ]:





# In[40]:


np.save('byte_bi_indx', byte_bi_indxes)
byte_bi_indxes = np.load('byte_bi_indx.npy')


# In[42]:


top_byte_bi = np.zeros((1000, 0))
for i in byte_bi_indxes:
    sliced = byte_bigram_vect[:, i].todense()
    top_byte_bi = np.hstack([top_byte_bi, sliced])


# In[53]:


byte_bi_df = pd.DataFrame(top_byte_bi, columns = np.take(byte_bigram(), byte_bi_indxes))
byte_bi_df


# In[60]:


byte_bi_df.to_csv('byte_bi.csv')
byte_bi_df = pd.read_csv('byte_bi.csv').drop('Unnamed: 0', axis = 1).fillna(0)
byte_bi_df['ID'] = result.ID
byte_bi_df.head()


# ## Total Features

# #### Adding 300 Byte bigram, 200 Opcode Bigram + Trigram + Tetragram (each), first 200 Image Pixels

# In[71]:


final_data = pd.concat([result_x, op_bi_df, op_tri_df, op_tetra_df, byte_bi_df,img_df], axis = 1, join = 'inner')
final_data = final_data.drop('ID', axis = 1)
final_data.head()


# In[72]:


final_data.to_csv('final_data.csv')
final_data = pd.read_csv('final_data.csv')


# In[ ]:




