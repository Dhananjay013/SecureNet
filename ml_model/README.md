# Malware Classification in PE Files using Machine Learning  

## Overview  
This project focuses on detecting malicious software in Portable Executable (PE) files by employing machine learning techniques. By leveraging a hybrid static malware analysis approach—combining PE header data, byte-n-grams, and opcode-n-grams features—we aim to enhance cybersecurity defenses. The trained model identifies whether a given PE file is malicious or benign.

## Project Resources  
### Datasets  
1. **PE Metadata Dataset**: A structured dataset containing metadata and header details of PE files. Available [here](https://www.kaggle.com/datasets/dasarijayanth/pe-header-data).  
2. **Raw Byte and Assembly (ASM) Files**: Extracted from the Microsoft Malware Classification Challenge (BIG 2015). Dataset link: [here](https://www.kaggle.com/competitions/malware-classification/data).  

## Feature Engineering and Extraction  
### PE Header Data (Dataset 1)  
- The dataset already provides feature values.  
- A script was developed to extract PE header attributes from executable files (.exe, .dll, etc.).  
- Extra-Trees classifier was utilized to identify the most important features.  

### Byte and ASM Data (Dataset 2)  
1. Organized raw byte and ASM files into separate directories and extracted file sizes as features.  
2. Extracted n-grams from byte files (n = 1, 2) and opcode patterns from assembly files (n = 1, 2, 3, 4).  
3. Converted assembly files into grayscale images and selected 200 top-performing pixels as features.  
4. Random Forest was applied for feature selection, reducing dimensionality while preserving relevant patterns.  

The final dataset comprises the following feature sets:  
- PE Header Features  
- Byte Unigrams  
- Opcode Unigrams  
- Top 300 Byte Bigrams  
- Top 200 Opcode Bigrams  
- Top 200 Opcode Trigrams  
- Top 200 Opcode Tetragrams  
- Top 200 Extracted Image Pixels  

## Model Training and Evaluation  
Several machine learning models were tested on the final feature set, including Gradient Boost, SVM, and Random Forest.  
- **Evaluation Metrics**: Accuracy, F1-score, and Confusion Matrix were used to assess model performance.  
- **Best Performing Model**: The Random Forest classifier outperformed others in malware detection.  

The trained Random Forest model can be downloaded from [this link](https://github.com/DasariJayanth/Malware-Detection-in-PE-files-using-Machine-Learning/blob/ce340fed1072ce4517e22c50d03e28b414bc3e87/models/RF_model.pkl).  

## Setup and Execution  
### Clone the Repository  
```sh  
git clone https://github.com/DasariJayanth/Malware-Detection-in-PE-files-using-Machine-Learning.git  
```

### Create and Activate Virtual Environment  
```sh  
python3 -m venv .venv  
```

If required, set execution policies:  
```sh  
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser  
```

Activate the environment:  
```sh  
source .venv/bin/activate  
```

### Install Dependencies  
```sh  
pip install -r requirements.txt  
```

### Feature Extraction & Prediction  
- Extract relevant features from your dataset following the scripts in `PE_Header(exe, dll files)/malware_test.py` and `Ngrams(byte, asm files)/N-grams.ipynb`.  
- Merge the extracted features before using the trained model, as demonstrated in `Malware Detection Model.ipynb`.  
- Load the pre-trained model (`models/RF_model.pkl`) and use it for predictions on new files.  

### Deactivate Virtual Environment  
```sh  
deactivate  
```

## Key Takeaways  
- The project integrates static analysis techniques with machine learning for malware detection.  
- Feature extraction techniques play a crucial role in improving model accuracy.  
- The Random Forest model demonstrated superior performance among tested algorithms.  

This project provides a structured approach to malware classification in PE files, offering valuable insights for cybersecurity applications.

