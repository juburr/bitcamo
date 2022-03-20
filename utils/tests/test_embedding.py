import unittest

import numpy as np

from models.malconv import MalConv
from utils.embedding import Matrix, reverse_lookup_kdtree, reverse_lookup_l2_distance

class TestMatrix(unittest.TestCase):
    def setUp(self):
        self.malconv = MalConv(attack_mode=True)
        self.matrix = Matrix(self.malconv)
    
    def test_reversable(self):
        """
        Tests that lookup() can be inverted back to its original
        byte value by using reverse_lookup() for every possible
        byte 0-255.

        E.g., reverse_lookup(lookup(5)) == 5
        E.g., reverse_lookup_prototype(lookup(5)) == 5

        Known failure: Looking up the 8D embedding for the special padding
        byte (256) and then calling reverse_lookup() will return 0 instead
        of 256. Excluded below by limiting range from 0 - 255.
        """
        for i in range(256):
            embedding = self.matrix.lookup(i)
            byte_rev1 = reverse_lookup_l2_distance(self.matrix.embedding_matrix, embedding)
            byte_rev2 = reverse_lookup_kdtree(self.matrix.reconstruction_kdtree, embedding)
            self.assertEqual(i, byte_rev1)
            self.assertEqual(i, byte_rev2)

    def test_lookup(self):
        """
        Tests that lookup() retreives the correct 8D embedding.

        This test first creates a byte array with each possible byte (0-255), such
        that uniqbytes = b'\x00\x01\x02\x03 ...'. We then run that array through
        the MalConv embedding layer. Finally, we simply make sure that the result
        for each record matches the result of our much easier and much faster
        lookup() function.
        """
        num_bytes = 256
        uniqbytes = np.array([i for i in range(num_bytes)], dtype=np.uint8).tobytes()
        embeddings = self.malconv.embed(uniqbytes)[0]

        for i in range(num_bytes):
            actual = embeddings[i].numpy()
            lookup = self.matrix.lookup(i)
        
            self.assertIsNone(np.testing.assert_array_equal(
                actual, lookup
            ))

if __name__ == '__main__':
    unittest.main()