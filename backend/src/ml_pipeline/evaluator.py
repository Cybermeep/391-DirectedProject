"""
Model evaluation utilities for the ML pipeline.

This module provides comprehensive evaluation tools for the intrusion
detection model including various metrics, visualization helpers,
and comparison utilities.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, Any, List, Optional, Tuple
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                            f1_score, confusion_matrix, classification_report,
                            roc_curve, auc, precision_recall_curve)
import logging
import json

logger = logging.getLogger(__name__)


class Evaluator:
    """
    Comprehensive model evaluation utilities.
    
    This class provides methods for evaluating classification models
    with various metrics, visualizations, and performance analysis.
    """
    
    def __init__(self):
        """Initialize the evaluator."""
        logger.info("Evaluator initialized")
    
    def evaluate_model(self, 
                      y_true: np.ndarray, 
                      y_pred: np.ndarray,
                      y_proba: Optional[np.ndarray] = None,
                      class_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Comprehensive model evaluation.
        
        Args:
            y_true (np.ndarray): True labels
            y_pred (np.ndarray): Predicted labels
            y_proba (np.ndarray, optional): Prediction probabilities
            class_names (List[str], optional): Names of classes
            
        Returns:
            Dict[str, Any]: Dictionary containing all evaluation metrics
        """
        logger.info("Evaluating model performance")
        
        # Basic metrics
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, average='weighted'),
            'recall': recall_score(y_true, y_pred, average='weighted'),
            'f1_score': f1_score(y_true, y_pred, average='weighted'),
            'confusion_matrix': confusion_matrix(y_true, y_pred),
            'classification_report': classification_report(y_true, y_pred, 
                                                          target_names=class_names)
        }
        
        # Per-class metrics
        precision_per_class = precision_score(y_true, y_pred, average=None)
        recall_per_class = recall_score(y_true, y_pred, average=None)
        f1_per_class = f1_score(y_true, y_pred, average=None)
        
        metrics['precision_per_class'] = precision_per_class
        metrics['recall_per_class'] = recall_per_class
        metrics['f1_per_class'] = f1_per_class
        
        # ROC-AUC if probabilities are available
        if y_proba is not None:
            # For binary classification
            if y_proba.shape[1] == 2:
                fpr, tpr, _ = roc_curve(y_true, y_proba[:, 1])
                metrics['roc_auc'] = auc(fpr, tpr)
                metrics['fpr'] = fpr
                metrics['tpr'] = tpr
                
                # Precision-Recall curve
                precision, recall, _ = precision_recall_curve(y_true, y_proba[:, 1])
                metrics['pr_precision'] = precision
                metrics['pr_recall'] = recall
                metrics['pr_auc'] = auc(recall, precision)
            
            # For multi-class
            elif y_proba.shape[1] > 2:
                # One-vs-rest ROC AUC
                from sklearn.metrics import roc_auc_score
                metrics['roc_auc_ovr'] = roc_auc_score(y_true, y_proba, multi_class='ovr')
                metrics['roc_auc_ovo'] = roc_auc_score(y_true, y_proba, multi_class='ovo')
        
        logger.info(f"Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"F1 Score: {metrics['f1_score']:.4f}")
        
        return metrics
    
    def print_evaluation(self, metrics: Dict[str, Any]) -> None:
        """
        Print formatted evaluation metrics.
        
        Args:
            metrics (Dict[str, Any]): Metrics dictionary from evaluate_model()
        """
        print("=" * 60)
        print("MODEL EVALUATION RESULTS")
        print("=" * 60)
        print(f"Accuracy: {metrics['accuracy']:.4f}")
        print(f"Precision (weighted): {metrics['precision']:.4f}")
        print(f"Recall (weighted): {metrics['recall']:.4f}")
        print(f"F1 Score (weighted): {metrics['f1_score']:.4f}")
        
        if 'roc_auc' in metrics:
            print(f"ROC AUC: {metrics['roc_auc']:.4f}")
        
        print("\n" + "=" * 60)
        print("CONFUSION MATRIX")
        print("=" * 60)
        print(metrics['confusion_matrix'])
        
        print("\n" + "=" * 60)
        print("CLASSIFICATION REPORT")
        print("=" * 60)
        print(metrics['classification_report'])
    
    def plot_confusion_matrix(self, 
                             metrics: Dict[str, Any],
                             class_names: Optional[List[str]] = None,
                             save_path: Optional[str] = None) -> None:
        """
        Plot confusion matrix.
        
        Args:
            metrics (Dict[str, Any]): Metrics dictionary from evaluate_model()
            class_names (List[str], optional): Names of classes
            save_path (str, optional): Path to save the plot
        """
        cm = metrics['confusion_matrix']
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=class_names or ['Class 0', 'Class 1'],
                   yticklabels=class_names or ['Class 0', 'Class 1'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Confusion matrix saved to {save_path}")
        
        plt.show()
    
    def plot_feature_importance(self, 
                               feature_importances: np.ndarray,
                               feature_names: List[str],
                               top_n: int = 20,
                               save_path: Optional[str] = None) -> None:
        """
        Plot feature importance.
        
        Args:
            feature_importances (np.ndarray): Feature importance scores
            feature_names (List[str]): Names of features
            top_n (int): Number of top features to show
            save_path (str, optional): Path to save the plot
        """
        # Create feature importance pairs
        importance_pairs = list(zip(feature_names, feature_importances))
        importance_pairs.sort(key=lambda x: x[1], reverse=True)
        
        # Get top N features
        top_features = importance_pairs[:top_n]
        names, scores = zip(*top_features)
        
        plt.figure(figsize=(10, 8))
        plt.barh(range(len(scores)), scores, align='center')
        plt.yticks(range(len(scores)), names)
        plt.xlabel('Feature Importance')
        plt.title(f'Top {top_n} Feature Importances')
        plt.gca().invert_yaxis()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Feature importance plot saved to {save_path}")
        
        plt.show()
    
    def plot_roc_curve(self, 
                      metrics: Dict[str, Any],
                      save_path: Optional[str] = None) -> None:
        """
        Plot ROC curve.
        
        Args:
            metrics (Dict[str, Any]): Metrics dictionary from evaluate_model()
            save_path (str, optional): Path to save the plot
            
        Raises:
            ValueError: If ROC curve data not available in metrics
        """
        if 'fpr' not in metrics or 'tpr' not in metrics:
            raise ValueError("ROC curve data not available. Provide y_proba to evaluate_model()")
        
        plt.figure(figsize=(8, 6))
        plt.plot(metrics['fpr'], metrics['tpr'], 
                label=f"ROC Curve (AUC = {metrics['roc_auc']:.3f})")
        plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curve')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"ROC curve saved to {save_path}")
        
        plt.show()
    
    def plot_precision_recall_curve(self,
                                   metrics: Dict[str, Any],
                                   save_path: Optional[str] = None) -> None:
        """
        Plot Precision-Recall curve.
        
        Args:
            metrics (Dict[str, Any]): Metrics dictionary from evaluate_model()
            save_path (str, optional): Path to save the plot
            
        Raises:
            ValueError: If PR curve data not available in metrics
        """
        if 'pr_precision' not in metrics or 'pr_recall' not in metrics:
            raise ValueError("PR curve data not available. Provide y_proba to evaluate_model()")
        
        plt.figure(figsize=(8, 6))
        plt.plot(metrics['pr_recall'], metrics['pr_precision'], 
                label=f"PR Curve (AUC = {metrics['pr_auc']:.3f})")
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"PR curve saved to {save_path}")
        
        plt.show()
    
    def compare_models(self, 
                      model_results: Dict[str, Dict[str, Any]],
                      save_path: Optional[str] = None) -> pd.DataFrame:
        """
        Compare multiple models.
        
        Args:
            model_results (Dict[str, Dict[str, Any]]): Dictionary of model results
                Format: {'model_name': {'accuracy': 0.95, 'f1_score': 0.94, ...}}
            save_path (str, optional): Path to save comparison
            
        Returns:
            pd.DataFrame: Comparison DataFrame
        """
        comparison_data = []
        
        for model_name, metrics in model_results.items():
            comparison_data.append({
                'Model': model_name,
                'Accuracy': metrics.get('accuracy', 0),
                'Precision': metrics.get('precision', 0),
                'Recall': metrics.get('recall', 0),
                'F1 Score': metrics.get('f1_score', 0)
            })
        
        df_comparison = pd.DataFrame(comparison_data)
        
        # Sort by F1 score (descending)
        df_comparison = df_comparison.sort_values('F1 Score', ascending=False)
        
        print("=" * 60)
        print("MODEL COMPARISON")
        print("=" * 60)
        print(df_comparison.to_string(index=False))
        
        if save_path:
            df_comparison.to_csv(save_path, index=False)
            logger.info(f"Model comparison saved to {save_path}")
        
        return df_comparison
    
    def save_metrics(self, metrics: Dict[str, Any], path: str) -> None:
        """
        Save metrics to JSON file.
        
        Args:
            metrics (Dict[str, Any]): Metrics dictionary
            path (str): Path to save JSON file
        """
        # Convert numpy arrays to lists for JSON serialization
        metrics_copy = metrics.copy()
        for key, value in metrics_copy.items():
            if isinstance(value, np.ndarray):
                metrics_copy[key] = value.tolist()
            elif isinstance(value, np.float64):
                metrics_copy[key] = float(value)
            elif isinstance(value, dict):
                # Handle nested dictionaries (like classification_report)
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, np.float64):
                        metrics_copy[key][sub_key] = float(sub_value)
        
        with open(path, 'w') as f:
            json.dump(metrics_copy, f, indent=2)
        
        logger.info(f"Metrics saved to {path}")