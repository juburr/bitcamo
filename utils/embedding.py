from matplotlib.pyplot import close
import tensorflow as tf
import numpy as np
from tqdm import tqdm
from joblib import Parallel, delayed
from scipy import spatial

def reverse_lookup_l2_distance(embedding_matrix, embedding):
    """
    Finds the closest byte to an 8-D embedding using an L2 distance metric.
    Allows for mapping backwards from embedded space to input space.

    Implemented as a top-level function to allow for use with parallel
    processing libraries.

    Parameters
    ----------
    embedding_matrix : tensorflow.python.framework.ops.EagerTensor
        A matrix containing 8-D embeddings for all 256 bytes.

    embedding : numpy.ndarray
        A single 8D embedding array to lookup.

    Returns
    -------
    byte: np.uint8
        Embedding space representation of the input byte.
    """
    distances = [tf.norm(eb - embedding, ord=2) for eb in embedding_matrix]
    byte_tf = tf.math.argmin(distances)
    byte_np = np.uint8(np.array(byte_tf, dtype=np.uint8).item())
    return byte_np

def reverse_lookup_kdtree(reconstruction_tree, embedding):
    """
    Finds the nearest byte to an 8-D embedding using a k-d tree.
    Allows for mapping backwards from embedded space to input space.

    Implemented as a top-level function to allow for use with parallel
    processing libraries.

    Parameters
    ----------
    reconstruction_tree: scipy.spatial.KDTree
        A kd-tree containing the 8-d embeddings for all 256 bytes.

    embedding : numpy.ndarray
        A single 8D embedding array to lookup.

    Returns
    -------
    byte: np.uint8
        Embedding space representation of the input byte.
    """
    return reconstruction_tree.query(embedding)[1].astype(np.uint8)

class Matrix:
    def __init__(
        self,
        malconv
    ):
        """
        The embedding matrix class provides some convenience functions for
        interacting directly with trained embedding layers. It provides the
        ability to perform both forward and backward lookups, the latter of
        which is a capability not provided by tf.keras, and unnecessary for
        most use cases.

        For adversarial attacks against MalConv, however, this is helpful
        because the embedding layer is non-differentiable. Many gradient-based
        attacks are therefore performed with respect to the embedded layer,
        after which they map backwards to input space. The reverse lookup
        functions provided by this class are one way of achieving this.

        Parameters
        ----------
        malconv : models.malconv.MalConv
            The MalConv model containing the embedding layer.
        """
        self.num_bytes = 256
        self.embedding_size = 8
        self.malconv = malconv

        # Data structures used for forward and reverse lookups through embedding layer
        self.embedding_matrix = self._setup_embedding_matrix()
        self.reconstruction_kdtree = self._setup_reconstruction_kdtree(self.embedding_matrix)

    def _setup_embedding_matrix(self):
        """
        Sets up an embedding matrix that allows for forward and reverse lookups
        through the embedding layer.

        Infinity is used for all 8 embedding values in matrix[256] because we don't
        ever want perturbed embeddings to map back to the special padding character.

        Returns
        -------
        embedding_matrix : tensorflow.python.framework.ops.EagerTensor
            A matrix containing 8-D embeddings for all 256 bytes.
        """
        uniqbytes = np.array([i for i in range(self.num_bytes)], dtype=np.uint8).tobytes()
        embedding_matrix = self.malconv.embed(uniqbytes)[0][:256]
        padding_byte_embedding = [[np.infty for _ in range(self.embedding_size)]]
        embedding_matrix = tf.concat([embedding_matrix, padding_byte_embedding], 0)
        return embedding_matrix

    def _setup_reconstruction_kdtree(self, embedding_matrix):
        """
        Sets up a kd-tree used for reverse lookups through the embedding layer.

        Parameters
        ----------
        embedding_matrix : tensorflow.python.framework.ops.EagerTensor
            A matrix containing 8-D embeddings for all 256 bytes.

        Returns
        -------
        scipy.spatial.KDTree
            A kd-tree containing the 8-d embeddings for all 256 bytes.
        """
        tree = spatial.KDTree(embedding_matrix)
        return tree
    
    def lookup(self, byte):
        """
        Performs a forward lookup on a single input byte, returning the
        corresponding 8D embedding.

        Parameters
        ----------
        byte : int
            Byte value to lookup.

        Returns
        -------
        numpy.ndarray
            Embedding space representation of the input byte.
        """
        return self.embedding_matrix[byte].numpy()
    
    def _reconstruction_l2(self, embeddings, parallel=True):
        """
        Performs a backwards mapping through the embedding layer, locating
        the closest byte to each of the 8-D embeddings that are supplied.
        Calls the L2 distance metric implementation in parallel.

        Parameters
        ----------
        embeddings : tensorflow.python.framework.ops.EagerTensor
            A Tensor with each row being an 8D embedding.

        parallel : bool
            A boolean signifying that parallel processing should be used.

        Returns
        -------
        numpy.ndarray
            The closest byte to each input row within the input space.
        """
        n = len(embeddings)

        if parallel:
            closest_bytes = Parallel(n_jobs=-1, backend="multiprocessing")(
                delayed(reverse_lookup_l2_distance)(self.embedding_matrix, embeddings[i]) for i in tqdm(range(n))
            )
        else:
            closest_bytes = []
            for i in tqdm(range(n)):
                closest_bytes.append(
                    reverse_lookup_l2_distance(self.embedding_matrix, embeddings[i])
                )

        return np.array(closest_bytes, dtype=np.uint8)

    def _reconstruction_kdtree(self, embeddings, parallel=True):
        """
        Performs a backwards mapping through the embedding layer, locating
        the closest byte to each of the 8-D embeddings that are supplied.
        Calls the kd-tree implementation in parallel.

        Parameters
        ----------
        embeddings : tensorflow.python.framework.ops.EagerTensor
            A Tensor with each row being an 8D embedding.

        parallel : bool
            A boolean signifying that parallel processing should be used.

        Returns
        -------
        numpy.ndarray
            The closest byte to each input row within the input space.
        """
        n = len(embeddings)

        if parallel:
            closest_bytes = Parallel(n_jobs=-1, backend="multiprocessing")(
                delayed(reverse_lookup_kdtree)(self.reconstruction_kdtree, embeddings[i]) for i in tqdm(range(n))
            )
        else:
            closest_bytes = []
            for i in tqdm(range(n)):
                closest_bytes.append(
                    reverse_lookup_kdtree(self.reconstruction_kdtree, embeddings[i])
                )

        return np.array(closest_bytes, dtype=np.uint8)

    def reconstruction(self, embeddings, kdtree=True, parallel=True):
        """
        Implementation of the reconstruction phase. Maps backwards through
        the embedding layer, locating the closest byte to each of the
        supplied 8-d embeddings.

        Parameters
        ----------
        embeddings : tensorflow.python.framework.ops.EagerTensor
            A Tensor with each row being an 8D embedding.

        kdtree : bool
            A boolean indicating that the KD Tree should be used instead of L2 norms.

        parallel : bool
            A boolean signifying that parallel processing should be used.

        Returns
        -------
        bytes
            The closest byte to each input row within the input space.
        """

        print('Reconstructing payload bytes from perturbed embedding layer:')

        if kdtree:
            print('   Reverse lookup method: kd-tree query')
            closest_bytes = self._reconstruction_kdtree(embeddings, parallel)
        else:
            print('   Reverse lookup method: L2 distance loop using argmin')
            closest_bytes = self._reconstruction_l2(embeddings, parallel)

        return closest_bytes.tobytes()