# Presentation Script
## Machine Learning Based Malware Detection System
### CSE 3968 — Major Project | Presented to: Ms. Kumari Manju

---

> **How to use this script:**
> Estimated total time: **12–15 minutes** (about 1–1.5 min per slide).
> Words in *italics* are delivery notes, not to be read aloud.
> Bold text = key terms to emphasise clearly.

---

## Slide 1 — Title

*Stand, make eye contact, speak confidently.*

"Good morning / afternoon, Ms. Kumari Manju.

I am [your name], and on behalf of our team — Aman Kumar, Harsh Kumar, Puja Kumari, and Shivam Kumar Singh — I would like to present our Major Project for CSE 3968: Machine Learning Concept 2.

Our project is titled **'Machine Learning Based Malware Detection System'**.

In this presentation, we will walk you through the problem we addressed, the datasets we used, our methodology, the models we built, and the results we achieved. We will also demonstrate how our system can analyse a real executable file and predict whether it is malware or not."

*Pause briefly, then move to next slide.*

---

## Slide 2 — Problem Statement

"Let us begin with why this project matters.

Traditional antivirus software works by matching files against a **database of known threat signatures**. This approach has a fundamental weakness — it only catches threats it has already seen before.

Modern malware authors are well aware of this. They use techniques like **polymorphism and code obfuscation** to constantly change the structure of their malware, making it unrecognisable to signature-based tools.

And the scale of the problem is growing. Cyberattacks are increasing year on year, targeting individuals, hospitals, banks, and governments alike.

This creates a clear need — an **intelligent, adaptive detection system** that can recognise malicious behaviour even from files it has never seen before. That is exactly what we set out to build."

---

## Slide 3 — Objectives

"With that motivation in mind, we defined five clear objectives for this project.

**First**, to develop a machine learning system that can classify executable files as either malicious or benign.

**Second**, to compare two powerful algorithms — **Random Forest and XGBoost** — on the EMBER benchmark dataset, which is a widely used research standard in malware detection.

**Third**, to go beyond just benchmarking — we wanted to build something practical. So we created a **custom feature extraction pipeline** that can take any real Windows `.exe` file and analyse it on the spot.

**Fourth**, to keep **false negatives as low as possible** — because missing a real piece of malware is far more dangerous than a false alarm.

And **fifth**, to deploy the final model as a **Streamlit web application**, so anyone can upload a file and get an instant result."

---

## Slide 4 — Datasets Used

"We worked with two completely different datasets, each serving a different purpose.

On the left, the **EMBER 2018 v2 dataset**. This is a benchmark dataset widely used in academic malware research. It contains pre-extracted static PE features from Windows executable files — things like byte histograms, section metadata, and import information. We sampled 20,000 records from it, with an almost perfectly balanced split of about 50% malware and 50% benign files. We used this dataset to rigorously compare our two algorithms.

On the right, **dataset underscore malwares dot csv**. This is a more practical dataset with 19,611 real executable samples and 79 PE-related features. It is slightly imbalanced — about 74% malware and 26% benign. We used this dataset to train a model for real-world file prediction.

Having two datasets allowed us to both validate our approach scientifically and demonstrate it practically."

---

## Slide 5 — Methodology

"Our methodology followed a clear five-step pipeline — as you can see across the top of this slide.

We start with **Data Collection**, feeding both datasets into the system.

Then **Preprocessing** — cleaning the data, dropping irrelevant columns like filenames, applying **StandardScaler** to normalise features, and using **SMOTE** on the EMBER pipeline to balance the classes.

Then **Model Training** — we trained both Random Forest and XGBoost classifiers.

Then **Evaluation** — measuring accuracy, precision, recall, F1-score, and ROC-AUC.

And finally **Deployment** — integrating the model into a Streamlit web app.

An important point — as shown at the bottom — we ran **two parallel pipelines**. The EMBER pipeline focused on algorithm comparison and included SMOTE and external validation. The PE dataset pipeline focused on practical deployment and included our custom `.exe` feature extractor with 77 features."

---

## Slide 6 — System Architecture

"Now let me show you how the system is structured end to end.

At the **Input Layer**, the system accepts either structured datasets or real uploaded `.exe` files.

These pass through the **Preprocessing Layer**, where features are scaled and, where needed, class imbalance is handled with SMOTE.

The processed feature vectors are then passed to the **Machine Learning Layer**, where Random Forest and XGBoost classifiers make the classification decision.

The trained models, along with the scaler and feature column mappings, are saved to disk using Joblib — this is our **Model Storage Layer**, which allows the system to serve predictions without retraining every time.

The **Prediction and Risk Layer** then produces not just a binary result but also a confidence score and a risk category — Low, Medium, High, or Critical.

And finally, everything is wrapped inside a **Streamlit Web Application**, so a user can simply upload a file and receive a result in seconds."

---

## Slide 7 — Results: EMBER Dataset

"Let us look at the results, starting with the EMBER dataset.

As you can see in the table, both models performed strongly. **XGBoost achieved 96% accuracy, 97% precision, 95% recall, an F1-score of 96%, and a ROC-AUC of 0.9923** — outperforming Random Forest across every metric.

The bar chart at the bottom makes this comparison easy to see visually.

But we went a step further. To test how well our model **generalises to new data it has never seen**, we took the XGBoost model trained on EMBER 2018 and tested it on the entirely separate **EMBER 2017 v2 dataset** — approximately 200,000 samples — without any retraining.

As shown in the orange box, the model maintained a strong **ROC-AUC of 0.9832**, even on this unseen data. The accuracy dropped to 84% and recall to 70%, which is expected when the data distribution shifts between training and testing sets — a well-known challenge in cross-dataset generalisation. But the near-perfect precision of 99% means the model almost never raised a false alarm."

---

## Slide 8 — Results: PE Malware Dataset

"On the practical PE malware dataset, both models performed even better — because this dataset's features are more directly tied to real executable structure.

**XGBoost achieved 99.24% accuracy, 99.05% precision, 99.93% recall, an F1-score of 99.49%, and a ROC-AUC of 0.9986.**

But the most important numbers are the ones in the four boxes below — the confusion matrix breakdown for Random Forest.

**2,916 true positives** — malware files correctly identified.
**971 true negatives** — benign files correctly cleared.
**Only 4 false negatives** — meaning just 4 malware files out of 2,920 total were missed.
And **32 false positives** — benign files incorrectly flagged.

As the note at the bottom states — only 4 malware files missed out of 2,920 gives us a recall of 99.86%. In a security context, this is what matters most."

---

## Slide 9 — Feature Importance

"One of the advantages of tree-based models like Random Forest is that they give us insight into **which features actually matter** for the prediction.

The horizontal bars here show the top 8 features identified by our model on the PE dataset.

The most important features are — **MinorOperatingSystemVersion**, **MajorLinkerVersion**, **MajorSubsystemVersion**, and **TimeDateStamp** — all of which come from the PE header.

This makes intuitive sense. Malware-compiled executables tend to have distinct patterns in their header metadata — different compiler versions, build timestamps, or subsystem flags compared to legitimate software. These structural signatures are what the model learns to distinguish.

This also validates our decision to use static PE features — they carry real discriminative signal."

---

## Slide 10 — Real Executable File Detection

"Now for the part that makes our project stand out — detecting malware in a **real uploaded executable file**.

The pipeline works in five steps, as shown across the top. The user uploads a `.exe` file. Our custom feature extractor then reads the file's PE structure and extracts exactly **77 features**. These are aligned to match the columns the model was trained on. **Both** trained models — Random Forest and XGBoost — then make independent predictions, and the results are shown side by side with confidence scores.

We tested this on a real file — **sf-x64.exe** — and both models agreed: the file is **Benign**. However, their confidence levels were notably different. **Random Forest returned 68% confidence**, indicating moderate certainty. **XGBoost returned 99.41% confidence** — a far more decisive result. Importantly, **zero features were missing** across both predictions — our extractor successfully captured all 77 required attributes.

This side-by-side output is intentional. When one model is uncertain, the other can provide a stronger signal — and in a security context, having **dual-model consensus** before clearing a file is always preferable.

At the bottom you can see our four **risk categories** used in the EMBER pipeline — Low, Medium, High, and Critical — based on the predicted malware probability. This gives security teams actionable information rather than just a yes or no answer."

---

## Slide 11 — Discussion

"Let us now take an honest look at what our system does well and where it has room to grow.

On the strengths side — our **dual-pipeline approach** is our biggest asset. We didn't just benchmark algorithms; we built something that works on real files. **XGBoost achieved 99.24% accuracy and ROC-AUC 0.9986**, while **Random Forest achieved 99.08% accuracy and ROC-AUC 0.9980** — both outstanding results on the PE dataset. The custom feature extractor works flawlessly with zero missing features on real executables. And the risk categorisation adds meaningful interpretability for end users.

However, we are also aware of the limitations. Our system performs **static analysis only** — it reads the file's structure without executing it. This means heavily obfuscated or packed malware could potentially evade detection. The drop in recall on the EMBER 2017 external test shows there is still a **cross-dataset generalisation gap**. And since our models are trained on specific datasets, they may struggle with entirely novel malware families that look nothing like what they were trained on.

It is also worth noting that on the real-world test file, **Random Forest returned only 68% confidence while XGBoost returned 99.41%** — a significant divergence. This highlights why relying on a single model at deployment boundaries can be risky, and why **dual-model consensus** is recommended in practice.

These limitations point directly to our future work."

---

## Slide 12 — Conclusion & Future Scope

"To summarise our work —

We successfully built and compared **Random Forest and XGBoost** on two real malware datasets. XGBoost consistently outperformed on both — achieving 96% accuracy and AUC 0.9923 on EMBER, and 99.24% accuracy and AUC 0.9986 on the PE dataset. Our custom PE feature extractor enables genuine real-time scanning of uploaded executables with zero missing features. And our risk categorisation system provides actionable security intelligence beyond a simple binary label.

For future work, we would like to integrate **dynamic analysis** — actually executing files in a sandbox to observe their behaviour. We also want to explore **deep learning approaches** like MalConv, which processes raw bytes directly without any manual feature engineering. And we plan to extend the system beyond Windows executables to also handle **Android APK files and cross-platform threats**.

Thank you for your time and attention, Ms. Kumari Manju. We are happy to take any questions."

*Bow slightly, step back, let the team be ready for Q&A.*

---

## Suggested Q&A Answers

**Q: Why did you choose XGBoost over other algorithms like SVM or Neural Networks?**
> XGBoost is specifically strong on structured tabular data, which is exactly what PE features are. It handles high-dimensional feature spaces efficiently, trains relatively fast, and its gradient boosting approach reduces both bias and variance. On our datasets it also outperformed Random Forest, confirming it was the right choice.

**Q: What is SMOTE and why did you only use it on the EMBER pipeline?**
> SMOTE — Synthetic Minority Oversampling Technique — generates synthetic samples of the minority class to balance the training data. We applied it on the EMBER pipeline because the dataset was nearly balanced and we wanted to ensure no bias. For the PE dataset, the class distribution was handled through stratified splitting, so SMOTE was not needed.

**Q: Why did the recall drop to 70% on the EMBER 2017 external test?**
> This is a cross-dataset generalisation issue. The model was trained on EMBER 2018 features, and the 2017 dataset has a different distribution — different malware families, different time period, slightly different feature patterns. A recall of 70% on completely unseen data, while maintaining ROC-AUC of 0.9832, actually shows the model has learned genuine patterns rather than overfitting to the training set.

**Q: What does the 68% confidence on the benign file mean, and why did XGBoost give 99.41%?**
> The 68% from Random Forest means 68% of its decision trees voted the file as benign — moderate confidence, not suspicious enough to flag as malware, but not a definitive clear either. XGBoost's 99.41% confidence, on the other hand, is highly decisive — it identified the file as benign with near-certainty. The divergence between the two models is actually useful information: in a real deployment, when Random Forest is uncertain, XGBoost's stronger signal can inform the final decision. A file like this — where one model is uncertain — might still be recommended for manual review before automatic clearance, even though both models agree on the label.

**Q: What is the difference between static and dynamic analysis?**
> Static analysis — which we use — examines the file's structure without running it. It is fast and safe but can be fooled by obfuscation. Dynamic analysis runs the file in a controlled sandbox environment and observes its actual behaviour — registry changes, network calls, file system activity. Dynamic analysis is more reliable for evasive malware but requires much more compute and time.

---

*End of Script*
