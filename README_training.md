# Phishing Detection Training Script

This script has been enhanced to support training a BERT model on the phishing email dataset for improved accuracy and recall.

## Features

- **Training Mode**: Train the model on the phishing email dataset
- **Evaluation**: Calculate accuracy, precision, recall, and F1-score
- **Detection Mode**: Use the trained model for phishing detection
- **Model Saving**: Save the trained model for future use

## Usage

### Training the Model

To train the model on the phishing email dataset:

```bash
python test.py train
```

This will:

1. Load the dataset from `data/phishing_email.csv`
2. Split the data into train/validation/test sets (70%/15%/15%)
3. Train the BERT model for 3 epochs
4. Evaluate on the test set and display metrics
5. Save the trained model to `./phishing_model/`

### Using the Model for Detection

After training, you can use the model for detection:

```bash
# Command line detection
python test.py "Your suspicious email text here"

# Interactive mode
python test.py
# Then enter text when prompted
```

### Expected Output

During training, you'll see:

- Dataset loading information
- Training progress with loss and metrics
- Final test results including:
  - Accuracy
  - Precision
  - Recall
  - F1-Score

## Requirements

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Dataset Format

The script expects a CSV file with columns:

- `text_combined`: The email text content
- `label`: Binary labels (0=ham, 1=phishing)

## Model Performance

The training will show you detailed metrics including:

- **Accuracy**: Overall correctness of predictions
- **Recall**: Ability to correctly identify phishing emails
- **Precision**: Accuracy of phishing predictions
- **F1-Score**: Harmonic mean of precision and recall

The model will be saved and can be reused for future predictions.

