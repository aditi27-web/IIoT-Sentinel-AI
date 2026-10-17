"""Educational ML pipeline. Demo training rows are synthetic, not real-world measurements."""
import os, pickle
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models.pkl")
FEATURES = ["cvss", "port", "is_public", "patch_available", "known_exploit", "asset_criticality"]

def make_training_data():
    rng = np.random.default_rng(21)
    X = []
    y = []
    for _ in range(1600):
        cvss = rng.uniform(0, 10)
        port = int(rng.choice([22, 80, 443, 502, 8080, 1883, 4840, 102, 0]))
        public = int(rng.random() < 0.35)
        patch = int(rng.random() < 0.65)
        exploit = int(rng.random() < 0.22)
        criticality = int(rng.integers(1, 4))
        # Transparent synthetic rule used to create demo labels.
        risk = cvss + public*1.0 + exploit*1.8 + (criticality-1)*0.65 - patch*0.25
        label = "Critical" if risk >= 10.1 else "High" if risk >= 7.7 else "Medium" if risk >= 4.8 else "Low"
        X.append([cvss, port, public, patch, exploit, criticality]); y.append(label)
    return np.array(X), np.array(y)

def train_models():
    if os.path.exists(MODEL_PATH):
        return
    X, y = make_training_data()
    models = {
        "Gradient Boosting": GradientBoostingClassifier(random_state=21),
        "Random Forest": RandomForestClassifier(n_estimators=120, random_state=21),
        "Decision Tree": DecisionTreeClassifier(max_depth=8, random_state=21),
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1500)),
        "MLP Neural Network": make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(32,16), max_iter=500, random_state=21))
    }
    for model in models.values():
        model.fit(X, y)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(models, f)

def predict_severity(data, model_name="Gradient Boosting"):
    train_models()
    with open(MODEL_PATH, "rb") as f:
        models = pickle.load(f)
    model = models.get(model_name, models["Gradient Boosting"])
    X = np.array([[float(data.get(k, 0)) for k in FEATURES]])
    return str(model.predict(X)[0])

def evaluate_models():
    X, y = make_training_data()
    X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=.25,random_state=21,stratify=y)
    models = {
        "Gradient Boosting": GradientBoostingClassifier(random_state=21),
        "Random Forest": RandomForestClassifier(n_estimators=120,random_state=21),
        "Decision Tree": DecisionTreeClassifier(max_depth=8,random_state=21),
        "Logistic Regression": make_pipeline(StandardScaler(),LogisticRegression(max_iter=1500)),
        "MLP Neural Network": make_pipeline(StandardScaler(),MLPClassifier(hidden_layer_sizes=(32,16),max_iter=500,random_state=21))
    }
    results=[]
    for name, model in models.items():
        model.fit(X_train,y_train)
        results.append({"model":name,"accuracy":round(accuracy_score(y_test,model.predict(X_test))*100,2)})
    return results
