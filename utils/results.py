from utils.statistics import combine_byte_distributions, print_distribution_tuples, print_duration_stats, print_stats_summary
from termcolor import colored
from datetime import timedelta

class GradientAttackResults:
    def __init__(
        self,
    ):
        self.processable = True
        self.attack_performed = False
        self.z_new_embermalconv_score = 0
        self.x_new = None
        self.x_new_len = 0
        self.x_new_hash = None
        self.x_new_code_hash = None
        self.x_new_embermalconv_score = 0
        self.evades_malconv = False
        self.evades_predetection = False
        self.payload_byte_distribution = None
        self.payload_size = 0
        self.iterations = 0
        self.duration = timedelta(0)
        self.reconstruction_duration = timedelta(0)

    def initialize(self, sample):
        # Attack Details
        self.payload_size = 0
        self.payload_byte_distribution = None
        self.iterations = 0
        self.duration = timedelta(0)
        self.reconstruction_duration = timedelta(0)

        # Perturbed Output File
        self.x_new = sample.x
        self.x_new_len = sample.x_len
        self.x_new_hash = sample.x_hash
        self.x_new_code_hash = sample.x_code_hash
        self.x_new_embermalconv_score = sample.x_embermalconv_score

        # Intermediate Results - predict(embed(x)) == predict(x) == predict_embedded(z)
        self.z_new_embermalconv_score = sample.x_embermalconv_score

        # Final Results
        if sample.benign:
            self.evades_malconv = self.x_new_embermalconv_score >= 0.5
        else:
            self.evades_malconv = self.x_new_embermalconv_score < 0.5
        self.evades_predetection = False

class FullAttackResults:
    def __init__(
        self,
    ):
        self.attack_count = 0
        self.best_result = GradientAttackResults()

        self.combined_iterations = 0
        self.combined_duration = timedelta(0)
        self.combined_reconstruction_duration = timedelta(0)

    def initialize(self, sample):
        self.attack_count = 0
        self.combined_iterations = 0
        self.combined_duration = timedelta(0)
        self.combined_reconstruction_duration = timedelta(0)

        self.best_result.initialize(sample)

class FinalResults:
    def __init__(
        self,
        samples,
        attack_config
    ):
        self.config = attack_config

        # Success totals
        self.num_samples = len(samples)
        self.num_evasions_embermalconv = 0
        self.num_evasions_predetection = 0
        self.num_processable = 0
        self.num_unprocessable = 0
        self.num_initially_correct = 0
        for s in samples:
            if s.results.best_result.processable:
                self.num_processable = self.num_processable + 1
            if s.results.best_result.evades_malconv:
                self.num_evasions_embermalconv = self.num_evasions_embermalconv + 1
            if s.results.best_result.evades_predetection:
                self.num_evasions_predetection = self.num_evasions_predetection + 1
            if s.benign == True and s.x_embermalconv_score < 0.5:
                self.num_initially_correct += 1
            if s.benign == False and s.x_embermalconv_score >= 0.5:
                self.num_initially_correct += 1
        self.num_initially_incorrect = len(samples) - self.num_initially_correct
        self.num_flipped = self.num_evasions_embermalconv - self.num_initially_incorrect
        self.num_unprocessable = self.num_samples - self.num_processable

        # Success totals (percentages)
        self.pct_evasions_embermalconv = 0.0
        self.pct_evasions_predetection = 0.0
        self.pct_processable = 0.0
        self.pct_unprocessable = 0.0
        self.pct_flipped = 0.0
        if self.num_samples > 0:
            self.pct_processable = (self.num_processable / self.num_samples) * 100
            self.pct_unprocessable = (self.num_unprocessable / self.num_samples) * 100
        if self.num_initially_correct > 0:
            self.pct_flipped = (self.num_flipped / self.num_initially_correct) * 100
        if self.num_processable > 0:
            self.pct_evasions_embermalconv = (self.num_evasions_embermalconv / self.num_processable) * 100
            self.pct_evasions_predetection = (self.num_evasions_predetection / self.num_processable) * 100

        # Final byte distributions of the payload
        self.byte_distribution_all = combine_byte_distributions(samples, False)
        self.byte_distribution_successful = combine_byte_distributions(samples, True)

        # Binary sizes
        self.binary_sizes = []
        self.binary_sizes_failures = []
        for s in samples:
            self.binary_sizes.append(s.x_len)
            if s.results.best_result.evades_malconv == False:
                self.binary_sizes_failures.append(s.x_len)

        # Payload sizes
        self.payload_sizes = []
        self.payload_sizes_atck = []
        self.payload_sizes_atck_fail = []
        self.payload_sizes_atck_succ = []
        for s in samples:
            psize = s.results.best_result.payload_size
            self.payload_sizes.append(psize)
            if s.results.best_result.attack_performed:
                self.payload_sizes_atck.append(psize)
                if s.results.best_result.evades_malconv:
                    self.payload_sizes_atck_succ.append(psize)
                else:
                    self.payload_sizes_atck_fail.append(psize)

        # Number of FGSM iterations
        self.gradient_iterations = []
        self.gradient_iterations_atck = []
        self.gradient_iterations_atck_fail = []
        self.gradient_iterations_atck_succ = []
        for s in samples:
            iterations = s.results.best_result.iterations
            self.gradient_iterations.append(iterations)
            if s.results.best_result.attack_performed:
                self.gradient_iterations_atck.append(iterations)
                if s.results.best_result.evades_malconv:
                    self.gradient_iterations_atck_succ.append(iterations)
                else:
                    self.gradient_iterations_atck_fail.append(iterations)

        # Attack durations
        self.attack_durations = []
        self.reconstruction_durations = []
        for s in samples:
            if s.results.best_result.attack_performed:
                self.attack_durations.append(s.results.combined_duration)
                self.reconstruction_durations.append(s.results.combined_reconstruction_duration)

        # MalConv classifications (initial)
        self.initial_scores_mal = 0
        self.ember_malconv_scores_initial = []
        self.ember_malconv_scores_initial_atck = []
        for s in samples:
            self.ember_malconv_scores_initial.append(s.x_embermalconv_score * 100)
            if s.results.best_result.attack_performed:
                self.ember_malconv_scores_initial_atck.append(s.x_embermalconv_score * 100)
            if s.x_embermalconv_score >= 0.5:
                self.initial_scores_mal = self.initial_scores_mal + 1
        self.initial_scores_tot = len(self.ember_malconv_scores_initial)
        self.initial_scores_ben = self.initial_scores_tot - self.initial_scores_mal
        self.initial_scores_ben_pct = (self.initial_scores_ben / self.initial_scores_tot) * 100
        self.initial_scores_mal_pct = (self.initial_scores_mal / self.initial_scores_tot) * 100

        # MalConv scores (perturbed embedded bytes)
        self.ember_malconv_scores_embedded = []
        self.ember_malconv_scores_embedded_atck = []
        self.ember_malconv_scores_embedded_atck_succ = []
        self.ember_malconv_scores_embedded_atck_fail = []
        for s in samples:
            z_score = s.results.best_result.z_new_embermalconv_score * 100
            self.ember_malconv_scores_embedded.append(z_score)
            if s.results.best_result.attack_performed:
                self.ember_malconv_scores_embedded_atck.append(z_score)
                if s.results.best_result.evades_malconv:
                    self.ember_malconv_scores_embedded_atck_succ.append(z_score)
                else:
                    self.ember_malconv_scores_embedded_atck_fail.append(z_score)

        # MalConv classifications (final)
        self.final_scores_mal = 0
        for s in samples:
            if s.results.best_result.x_new_embermalconv_score >= 0.5:
                self.final_scores_mal = self.final_scores_mal + 1
        self.final_scores_tot = len(samples)
        self.final_scores_ben = self.final_scores_tot - self.final_scores_mal
        self.final_scores_ben_pct = (self.final_scores_ben / self.final_scores_tot) * 100
        self.final_scores_mal_pct = (self.final_scores_mal / self.final_scores_tot) * 100

        # MalConv scores (final)
        self.ember_malconv_scores = []
        self.ember_malconv_scores_atck = []
        self.ember_malconv_scores_atck_fail = []
        self.ember_malconv_scores_atck_succ = []
        for s in samples:
            score = s.results.best_result.x_new_embermalconv_score * 100
            self.ember_malconv_scores.append(score)
            if s.results.best_result.attack_performed:
                self.ember_malconv_scores_atck.append(score)
                if s.results.best_result.evades_malconv:
                    self.ember_malconv_scores_atck_succ.append(score)
                else:
                    self.ember_malconv_scores_atck_fail.append(score)

    def print(self):
        if self.num_samples == 1 and self.config.verbose == False:
            return
        if self.num_processable == 0:
            print('No samples were attacked.')
            return

        print(colored('[Cumulative Results]', 'blue', 'on_yellow'))
        print(f'Total File Count: {self.num_samples}')
        print(f'   Unprocessable: {self.num_unprocessable} ({self.pct_unprocessable:.4f}%)')
        print('Initial Classifications:')
        print(f'   Malicious: {self.initial_scores_mal} ({self.initial_scores_mal_pct:.4f}%)')
        print(f'   Benign: {self.initial_scores_ben} ({self.initial_scores_ben_pct:.4f}%)')
        print('Final Classifications:')
        print(f'   Malicious: {self.final_scores_mal} ({self.final_scores_mal_pct:.4f}%)')
        print(f'   Benign: {self.final_scores_ben} ({self.final_scores_ben_pct:.4f}%)')
        print(f'Successful MalConv Attacks: {self.num_flipped} / {self.num_initially_correct} ({self.pct_flipped:.4f}%)')
        print(f'Total MalConv Evasions: {self.num_evasions_embermalconv} / {self.num_samples} ({self.pct_evasions_embermalconv:.4f}%)')
        if self.config.evade_predetection == True:
            print(f'Total Predetection Evasions: {self.num_evasions_predetection} / {self.num_samples} ({self.pct_evasions_predetection:.4f}%)')
        print('Statistics:')

        if self.config.verbose:
            print(f'   Payload Byte Distribution (Successful): {self.byte_distribution_successful}')
        else:
            top_bytes = self.byte_distribution_successful.most_common(3)
            print(f'   Payload Byte Distribution (Successful - Top 3):')
            print_distribution_tuples(top_bytes, '      ')

        print(f'   Binary Size (success cases):')
        print_stats_summary(self.binary_sizes, integers_only=True, include_sum=False)

        print(f'   Binary Size (failure cases):')
        print_stats_summary(self.binary_sizes_failures, integers_only=True, include_sum=False)

        print(f'   Payload Size (overlay):')
        print_stats_summary(self.payload_sizes, integers_only=True, include_sum=False)

        print(f'   Payload Size (overlay - attacks only):')
        print_stats_summary(self.payload_sizes_atck, integers_only=True, include_sum=False)

        print(f'   Payload Size (overlay - successful attacks only):')
        print_stats_summary(self.payload_sizes_atck_succ, integers_only=True, include_sum=False)

        print(f'   Payload Size (overlay - failed attacks only):')
        print_stats_summary(self.payload_sizes_atck_fail, integers_only=True, include_sum=False)

        print(f'   FGSM iterations:')
        print_stats_summary(self.gradient_iterations, integers_only=True)

        print(f'   FGSM iterations (attacks only):')
        print_stats_summary(self.gradient_iterations_atck, integers_only=True)

        print(f'   FGSM iterations (successful attacks only):')
        print_stats_summary(self.gradient_iterations_atck_succ, integers_only=True)

        print(f'   FGSM iterations (failed attacks only):')
        print_stats_summary(self.gradient_iterations_atck_fail, integers_only=True)

        print(f'   Attack duration:')
        print_duration_stats(self.attack_durations)

        print(f'   Reconstruction phase duration:')
        print_duration_stats(self.reconstruction_durations)

        print(f'  EMBER MalConv Scores (Pre-Attack - all samples):')
        print_stats_summary(self.ember_malconv_scores_initial, include_sum=False)

        print(f'  EMBER MalConv Scores (Perturbed Embeddings, Pre-Reconstruction - all samples):')
        print_stats_summary(self.ember_malconv_scores_embedded, include_sum=False)

        print(f'  EMBER MalConv Scores (Perturbed Embeddings, Pre-Reconstruction - attacks only):')
        print_stats_summary(self.ember_malconv_scores_embedded_atck, include_sum=False)

        print(f'  EMBER MalConv Scores (Perturbed Embeddings, Pre-Reconstruction - successful attacks only):')
        print_stats_summary(self.ember_malconv_scores_embedded_atck_succ, include_sum=False)

        print(f'  EMBER MalConv Scores (Perturbed Embeddings, Pre-Reconstruction - failed attacks only):')
        print_stats_summary(self.ember_malconv_scores_embedded_atck_fail, include_sum=False)

        print(f'  EMBER MalConv Scores (Post-Attack):')
        print_stats_summary(self.ember_malconv_scores, include_sum=False)

        print(f'  EMBER MalConv Scores (Post-Attack - attacked samples only):')
        print_stats_summary(self.ember_malconv_scores_atck, include_sum=False)

        print(f'  EMBER MalConv Scores (Post-Attack - successful attacks only):')
        print_stats_summary(self.ember_malconv_scores_atck_succ, include_sum=False)

        print(f'  EMBER MalConv Scores (Post-Attack - failed attacks only):')
        print_stats_summary(self.ember_malconv_scores_atck_fail, include_sum=False)