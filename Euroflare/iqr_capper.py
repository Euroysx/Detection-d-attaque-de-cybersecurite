# ================================================================
# iqr_capper.py — Module IQRCapper
#
# Ce fichier doit être dans le même dossier que main.py ET
# dans le même dossier que le notebook.
#
# Pourquoi un fichier séparé ?
# joblib sauvegarde le chemin complet de la classe.
# Si elle est définie dans __main__ (notebook), elle ne peut
# pas être rechargée depuis main.py.
# En la définissant dans un module séparé, joblib sauvegarde
# 'iqr_capper.IQRCapper' — rechargeable depuis n'importe où.
# ================================================================

import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin


class IQRCapper(BaseEstimator, TransformerMixin):
    """
    Transformer reproductible — Capping des valeurs aberrantes (Tukey IQR).

    Méthode : borne_basse = Q1 - factor*IQR | borne_haute = Q3 + factor*IQR
    Les valeurs hors bornes sont ramenées à la borne (pas supprimées).

    Paramètres
    ----------
    factor : float, défaut=1.5
        1.5 = outliers modérés | 3.0 = extrêmes seulement
    """

    def __init__(self, factor=1.5):
        self.factor = factor

    def fit(self, X, y=None):
        X_df        = pd.DataFrame(X)
        Q1          = X_df.quantile(0.25)
        Q3          = X_df.quantile(0.75)
        IQR         = Q3 - Q1
        self.lower_ = Q1 - self.factor * IQR
        self.upper_ = Q3 + self.factor * IQR
        return self

    def transform(self, X, y=None):
        return pd.DataFrame(X).clip(
            lower=self.lower_.values,
            upper=self.upper_.values,
            axis=1
        ).values
