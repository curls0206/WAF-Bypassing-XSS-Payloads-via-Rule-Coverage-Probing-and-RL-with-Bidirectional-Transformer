import re
from pathlib import Path

import numpy as np
import tensorflow as tf
from tensorflow import keras
from transformers import BertTokenizer


def preprocess_payload(payload: str) -> str:
    text = payload
    text = re.sub(r'http[s]?://[^\s"<>]+', 'http://u', text)
    text = re.sub(r'\d+', '0', text)
    return text


class PositionalEmbedding(keras.layers.Layer):
    def __init__(self, length=128, inputDim=30522, outputDim=768, **kwargs):
        super().__init__(**kwargs)
        self.length = length
        self.inputDim = inputDim
        self.outputDim = outputDim
        self.tokenEmbeddings = keras.layers.Embedding(
            input_dim=inputDim,
            output_dim=outputDim,
            name="token_embedding",
        )
        self.positionEmbeddings = keras.layers.Embedding(
            input_dim=length,
            output_dim=outputDim,
            name="position_embedding",
        )

    def call(self, inputs):
        seq_len = tf.shape(inputs)[-1]
        positions = tf.range(start=0, limit=seq_len, delta=1)
        embeddedTokens = self.tokenEmbeddings(inputs)
        embeddedPositions = self.positionEmbeddings(positions)
        return embeddedTokens + embeddedPositions

    def get_config(self):
        cfg = super().get_config()
        cfg.update(
            {
                "length": self.length,
                "inputDim": self.inputDim,
                "outputDim": self.outputDim,
            }
        )
        return cfg


class TransformerEncoder(keras.layers.Layer):
    def __init__(self, embedDim, numHeads, denseDim, rate=0.1, **kwargs):
        super().__init__(**kwargs)
        self.embedDim = int(embedDim)
        self.numHeads = int(numHeads)
        self.denseDim = int(denseDim)
        self.rate = float(rate)

        self.att = keras.layers.MultiHeadAttention(
            num_heads=self.numHeads,
            key_dim=self.embedDim,
            name="multi_head_attention",
        )
        self.layernorm1 = keras.layers.LayerNormalization(epsilon=1e-6, name="layer_normalization")
        self.layernorm2 = keras.layers.LayerNormalization(epsilon=1e-6, name="layer_normalization_1")
        self.dropout1 = keras.layers.Dropout(self.rate, name="dropout")
        self.dropout2 = keras.layers.Dropout(self.rate, name="dropout_1")

        self.dense = keras.layers.Dense(self.denseDim, activation="relu", name="dense")
        self.dense_1 = keras.layers.Dense(self.embedDim, name="dense_1")

    def call(self, inputs, training=False):
        attn_output = self.att(inputs, inputs)
        attn_output = self.dropout1(attn_output, training=training)
        out1 = self.layernorm1(inputs + attn_output)

        ffn_out = self.dense(out1)
        ffn_out = self.dense_1(ffn_out)
        ffn_out = self.dropout2(ffn_out, training=training)
        return self.layernorm2(out1 + ffn_out)

    def get_config(self):
        cfg = super().get_config()
        cfg.update(
            {
                "embedDim": self.embedDim,
                "numHeads": self.numHeads,
                "denseDim": self.denseDim,
                "rate": self.rate,
            }
        )
        return cfg


def build_skeleton_model(
    max_len: int,
    vocab_size: int = 20000,
    embedDim: int = 768,
    denseDim: int = 32,
    numHeads: int = 2,
):
    inputs = keras.Input(shape=(max_len,), dtype="int32", name="input_ids")
    x = PositionalEmbedding(length=max_len, inputDim=vocab_size, outputDim=embedDim, name="positional_embedding")(inputs)
    x = TransformerEncoder(embedDim=embedDim, numHeads=numHeads, denseDim=denseDim, name="transformer_encoder")(x)
    x = keras.layers.GlobalAveragePooling1D(name="pool")(x)
    outputs = keras.layers.Dense(2, activation="softmax", name="classifier")(x)
    return keras.Model(inputs=inputs, outputs=outputs, name="xss_transformer_skeleton")


def _resolve_model_path(model_path: str) -> Path:
    raw = Path(model_path).expanduser()
    if raw.is_absolute():
        return raw

    module_dir = Path(__file__).resolve().parent
    candidates = [
        Path.cwd() / raw,
        module_dir / raw,
        module_dir / raw.name,
    ]
    for c in candidates:
        if c.exists():
            return c.resolve()
    return candidates[0].resolve()


class XSSDetector:
    def __init__(self, model_path: str, max_len: int = 600, tokenizer_name: str = "prajjwal1/bert-tiny"):
        self.max_len = max_len
        self.vocab_size = 20000
        self.tokenizer = BertTokenizer.from_pretrained(tokenizer_name)
        resolved = _resolve_model_path(model_path)

        custom_objects = {
            "PositionalEmbedding": PositionalEmbedding,
            "TransformerEncoder": TransformerEncoder,
        }
        if resolved.suffix.lower() == ".keras":
            self.model = keras.models.load_model(
                str(resolved),
                custom_objects=custom_objects,
                compile=False,
            )
            input_shape = getattr(self.model, "input_shape", None)
            if isinstance(input_shape, tuple) and len(input_shape) >= 2 and isinstance(input_shape[1], int):
                self.max_len = int(input_shape[1])
        else:
            self.model = build_skeleton_model(
                max_len=self.max_len,
                embedDim=768,
                denseDim=32,
                numHeads=2,
                vocab_size=self.vocab_size,
            )
            self.model.load_weights(str(resolved))
        self.model.trainable = False

    def _encode(self, text: str):
        enc = self.tokenizer(
            text,
            padding="max_length",
            truncation=True,
            max_length=self.max_len,
            return_tensors="tf",
        )
        ids = enc["input_ids"].numpy()
        ids = np.where(ids < self.vocab_size, ids, 1)
        return [tf.convert_to_tensor(ids, dtype=tf.int32)]

    def predict_proba(self, payload: str) -> float:
        text = preprocess_payload(payload)
        inputs = self._encode(text)
        preds = self.model.predict(inputs, verbose=0)
        if isinstance(preds, list):
            preds = preds[0]
        preds = np.asarray(preds)
        if preds.ndim != 2 or preds.shape[0] == 0:
            return 1.0
        if preds.shape[1] >= 2:
            return float(preds[0][1])
        return float(preds[0][0])

    def is_xss(self, payload: str) -> int:
        return int(self.predict_proba(payload) >= 0.5)
