try:
    import nlu
    NLU_AVAILABLE = True
except Exception:
    NLU_AVAILABLE = False
def classify_text(text):
    """
    Returns a dict with document and spam score or an error if nlu not available.
    Expect `text` as a string.
    """
    if not NLU_AVAILABLE:
        return {"error": "nlu library not available"}
    try:
        spam_df = nlu.load('classify.spam.use').predict([text], output_level='document')
        # spam_df is assumed to be a pandas-like DF; handle gracefully
        doc = spam_df["document"].iloc[0] if "document" in spam_df else text
        spam_score = None
        if "spam" in spam_df:
            try:
                spam_score = float(spam_df["spam"].iloc[0])
            except Exception:
                spam_score = spam_df["spam"].iloc[0]
        return {"document": doc, "spam": spam_score}
    except Exception as e:
        return {"error": str(e)}
