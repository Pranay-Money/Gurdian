"""
ML Pipeline Custom Exceptions
"""
import sys
import traceback
from typing import Any


def error_message_detail(error: Exception, error_detail: Any) -> str:
    """Extract detailed error message with file name and line number."""
    _, _, exc_tb = error_detail.exc_info()
    if exc_tb is None:
        return str(error)

    file_name = exc_tb.tb_frame.f_code.co_filename
    line_no = exc_tb.tb_lineno
    error_message = (
        f"Error occurred in Python script: [{file_name}] "
        f"Line: [{line_no}] Error: [{str(error)}]"
    )
    return error_message


class MLPipelineException(Exception):
    """Base exception for ML pipeline."""

    def __init__(self, message: str, error_detail: Any = None):
        super().__init__(message)
        self.error_message = message
        if error_detail:
            self.error_message = error_message_detail(message, error_detail)

    def __str__(self) -> str:
        return self.error_message


class DataIngestionException(MLPipelineException):
    """Exception for data ingestion errors."""
    pass


class FeatureEngineeringException(MLPipelineException):
    """Exception for feature engineering errors."""
    pass


class ModelTrainingException(MLPipelineException):
    """Exception for model training errors."""
    pass


class ModelEvaluationException(MLPipelineException):
    """Exception for model evaluation errors."""
    pass


class ModelExportException(MLPipelineException):
    """Exception for model export errors."""
    pass


class ConfigurationException(MLPipelineException):
    """Exception for configuration errors."""
    pass