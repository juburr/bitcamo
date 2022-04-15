from models.malconv import TARGET_BENIGN

class AttackConfig:
    def __init__(
        self,
    ):
        self.bengin_inputs = False
        self.payload_size = 0
        self.initialization_method = ''
        self.reconstuct_full_file = False
        self.reconstruct_parallel = False
        self.reconstruct_kdtrees = True
        self.verbose = False
        self.evade_predetection = False
        self.max_iterations = 8
        self.epsilon = 1.0
        self.y_target = TARGET_BENIGN
        self.optimize_payload_size = False