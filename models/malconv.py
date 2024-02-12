import os
import sys

import numpy as np
import tensorflow as tf

from tensorflow.keras import Model, metrics
from tensorflow.keras.layers import Dense, Conv1D, GlobalMaxPooling1D, Input, Embedding, Multiply
from tensorflow.keras.models import load_model
from tensorflow.keras.optimizers import SGD

KERNEL_SIZE = 512
TARGET_MALICIOUS = [[1.0]]
TARGET_BENIGN = [[0.0]]

class MalConv:
    """
    A pretrained implementation of MalConv using the EMBER dataset. Run samples
    through the model using the predict() function.

    All other functions are convenience functions used for attacking the
    underlying model. In particular, embed() allows you to run a sample through
    the embedding layer only, and predict_embedded() allows you to run a
    prediction using the embedded representation of the sample as input. Therefore,
    predict(x) is equivalent to predict_embedded(embed(x)).

    References
    ----------
    Title: Malware Detection by Eating a Whole EXE (2017)
    Authors: E. Raff, J. Barker, J. Sylvester, R. Brandon, B. Catanzaro & C. Nicholas
    URL: https://arxiv.org/pdf/1710.09435.pdf

    Title: EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models (2018)
    Authors: H. Anderson & P. Roth
    URL: https://arxiv.org/pdf/1804.04637.pdf
    """

    def __init__(self, attack_mode=False):
        self.attack_mode = attack_mode
        self.padding_char = 256
        self.dict_size = 257
        self.input_size = 1048576 # 1 MB (2^20)
        self.embedding_size = 8
        self.malicious_threshold = 0.5
        self.model_path = self._get_model_path()
        self.model = self._load_full_model()
        self.embedder = None
        self.embedding_space_model = None

        # Conserve memory by only loading the additional models when in attack mode
        if attack_mode:
            self.embedder = self._load_embedder()
            self.embedding_space_model = self._load_embedding_space_model()

    def _get_model_path(self):
        """
        Returns the path to the MalConv weights file.

        Returns
        -------
        str
            The absolute path to the weights file.
        """
        root = os.path.dirname(os.path.realpath(sys.argv[0]))
        return os.path.join(root, 'models/ember_malconv.h5')
    
    def _load_embedder(self):
        """
        Loads the partial model that contains the input layer and embedding
        layer of the MalConv model. This allows attackers to easily transform
        input bytes 'x' to their embedded representation 'z'.

        Returns
        -------
        tensorflow.python.keras.engine.sequential.Sequential
            A partial model containing the input and embedding layers only.
        """
        return tf.keras.Sequential([
            self.model.layers[0],
            self.model.layers[1]
        ])

    def _load_full_model(self):
        """
        Loads the MalConv model from a pre-trained weights file trained by
        the EMBER dataset.

        Returns
        -------
        tensorflow.python.keras.engine.functional.Functional
            A pre-trained MalConv model
        """
        model = load_model(self.model_path, compile = False)
        lr_schedule = tf.keras.optimizers.schedules.ExponentialDecay(
            initial_learning_rate=0.01,
            decay_steps=10000,
            decay_rate=1e-3)
        model.compile(
            loss='binary_crossentropy',
            optimizer=SGD(momentum=0.9, nesterov=True, learning_rate=lr_schedule),
            metrics=[metrics.binary_accuracy]
        )
        return model
    
    def _load_embedding_space_model(self):
        """
        Loads a partial MalConv model with the initial embedding layer
        removed. Input to this model should be the embedded representation
        of the file bytes. With the embedding layer removed, this partial
        model is differentiable and ideal for computing gradient-based
        adversarial examples.

        Returns
        -------
        tensorflow.python.keras.engine.functional.Functional
            A partial model with the embedding layer removed.
        """
        inp = Input(shape=(self.input_size, self.embedding_size))
        filt = Conv1D( filters=128, kernel_size=500, strides=500, use_bias=True, activation='relu', padding='valid' )(inp)
        attn = Conv1D( filters=128, kernel_size=500, strides=500, use_bias=True, activation='sigmoid', padding='valid')(inp)
        gated = Multiply()([filt,attn])
        feat = GlobalMaxPooling1D()( gated )
        dense = Dense(128, activation='relu')(feat)
        outp = Dense(1, activation='sigmoid')(dense)

        emb_model = Model( inp, outp )
        lr_schedule = tf.keras.optimizers.schedules.ExponentialDecay(
            initial_learning_rate=0.01,
            decay_steps=10000,
            decay_rate=1e-3)
        emb_model.compile(
            loss='binary_crossentropy',
            optimizer=SGD(momentum=0.9, nesterov=True, learning_rate=lr_schedule),
            metrics=[metrics.binary_accuracy]
        )

        emb_model.layers[1].set_weights(self.model.layers[2].get_weights()) # conv1d_1
        emb_model.layers[2].set_weights(self.model.layers[3].get_weights()) # conv1d_2
        emb_model.layers[3].set_weights(self.model.layers[4].get_weights()) # multiply_1
        emb_model.layers[4].set_weights(self.model.layers[5].get_weights()) # global_max_pooling1d_1
        emb_model.layers[5].set_weights(self.model.layers[6].get_weights()) # dense_1
        emb_model.layers[6].set_weights(self.model.layers[7].get_weights()) # dense_2

        return emb_model

    def determine_success(self, y_target, y_hat):
        success = False
        if y_target == TARGET_MALICIOUS:
            success = True if y_hat > self.malicious_threshold else False
        else:
            success = True if y_hat < self.malicious_threshold else False
        return success

    def _pad(self, x):
        """
        MalConv uses a fixed size input of 1 MB. All executables smaller
        than that need to padded with a special character to fill the
        remaining space.

        Parameters
        ----------
        x : bytes
            Byte representation of the input file to predict.

        Returns
        -------
        b : numpy.ndarray
            Padded version of the original input
        """
        b = np.ones((self.input_size,), dtype=np.uint16) * self.padding_char
        x = np.frombuffer(x[:self.input_size], dtype=np.uint8)
        b[:len(x)] = x
        return b
    
    def embed(self, x):
        """
        Runs a sample through the embedding layer only, transforming input bytes
        'x' into corresponding embedded bytes 'z'.

        Parameters
        ----------
        x : bytes
            Byte representation of a Windows PE file.

        Returns
        -------
        z : tensorflow.python.framework.ops.EagerTensor
            Embedding space representation of a Windows PE file.
        """
        if self.attack_mode == False:
            raise Exception('function embed() is only available in attack mode')

        return self.embedder(self._pad(x).reshape(1, -1))
    
    def predict_embedded(self, z):
        """
        Runs already embedded bytes through the remainder of the MalConv
        model, skipping the initial embedding step, and returning the final
        prediction.
        
        Parameters
        ----------
        z : tensorflow.python.framework.ops.EagerTensor
            Embedding space representation of a Windows PE file.

        Returns
        -------
        y_hat : numpy.float32
            Model prediction between 0 (benign) and 1 (malicious).
        """
        if self.attack_mode == False:
            raise Exception('function predict_embedded() is only available in attack mode')
        return self.embedding_space_model.predict(z)[0][0]
    
    def predict(self, x):
        """
        Runs a sample through the full MalConv model and returns its prediction.
        
        Parameters
        ----------
        x : bytes
            Byte representation of a Windows PE file.

        Returns
        -------
        y_hat : numpy.float32
            Model prediction between 0 (benign) and 1 (malicious).
        """
        return self.model.predict(self._pad(x).reshape(1, -1))[0][0]

    def evasion_achieved(self, y_hat, y_target):
        """
        Determines if evasion of MalConv has been achieved

        Parameters
        ----------
        y_hat : numpy.float32
            MalConv prediction score
        y_target : list
            Target class of the adversarial attack (benign or malcious)

        Returns
        -------
        bool
            True if MalConv has been evaded.
        """
        if y_hat >= self.malicious_threshold and y_target == TARGET_MALICIOUS:
            return True
        if y_hat < self.malicious_threshold and y_target == TARGET_BENIGN:
            return True
        return False