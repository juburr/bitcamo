from utils.logs import format_timedelta
from utils.statistics import combine_byte_distributions, print_distribution_tuples
from termcolor import colored
from datetime import timedelta
from statistics import mean, median, stdev

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
        binary_sizes_success = []
        binary_sizes_failure = []
        for s in samples:
            if s.results.best_result.evades_malconv:
                binary_sizes_success.append(s.x_len)
            else:
                binary_sizes_failure.append(s.x_len)

        self.binsize_success_tot = len(binary_sizes_success)
        self.binsize_success_avg = 0.0
        self.binsize_success_med = 0.0
        self.binsize_success_std = 0.0
        self.binsize_success_max = 0
        self.binsize_success_min = 0
        if len(binary_sizes_success) > 0:
            self.binsize_success_avg = mean(binary_sizes_success)
            self.binsize_success_med = median(binary_sizes_success)
            self.binsize_success_max = max(binary_sizes_success)
            self.binsize_success_min = min(binary_sizes_success)
        if len(binary_sizes_success) > 1:
            self.binsize_success_std = stdev(binary_sizes_success)

        self.binsize_failure_tot = len(binary_sizes_failure)
        self.binsize_failure_avg = 0.0
        self.binsize_failure_med = 0.0
        self.binsize_failure_std = 0.0
        self.binsize_failure_max = 0
        self.binsize_failure_min = 0
        if len(binary_sizes_failure) > 0:
            self.binsize_failure_avg = mean(binary_sizes_failure)
            self.binsize_failure_med = median(binary_sizes_failure)
            self.binsize_failure_max = max(binary_sizes_failure)
            self.binsize_failure_min = min(binary_sizes_failure)
        if len(binary_sizes_failure) > 1:
            self.binsize_failure_std = stdev(binary_sizes_failure)

        # Payload sizes, regardless of success status
        payload_sizes = []
        for s in samples:
            payload_sizes.append(s.results.best_result.payload_size)
        self.payload_overlay_size_avg = mean(payload_sizes)
        self.payload_overlay_size_med = median(payload_sizes)
        self.payload_overlay_size_std = 0.0
        if len(payload_sizes) > 1:
            self.payload_overlay_size_std = stdev(payload_sizes)
        self.payload_overlay_size_max = max(payload_sizes)
        self.payload_overlay_size_min = min(payload_sizes)

        # Payload sizes (successful attacks only)
        success_payload_sizes = []
        for s in samples:
            if s.results.best_result.attack_performed and s.results.best_result.evades_malconv:
                success_payload_sizes.append(s.results.best_result.payload_size)
        self.success_payload_overlay_size_avg = mean(success_payload_sizes)
        self.success_payload_overlay_size_med = median(success_payload_sizes)
        self.success_payload_overlay_size_std = 0.0
        if len(success_payload_sizes) > 1:
            self.success_payload_overlay_size_std = stdev(success_payload_sizes)
        self.success_payload_overlay_size_max = max(success_payload_sizes)
        self.success_payload_overlay_size_min = min(success_payload_sizes)

        # Number of FGSM iterations for best result
        attack_iterations = []
        for s in samples:
            attack_iterations.append(s.results.best_result.iterations)
        self.iterations_avg = mean(attack_iterations)
        self.iterations_med = median(attack_iterations)
        self.iterations_std = 0.0
        if len(attack_iterations) > 1:
            self.iterations_std = stdev(attack_iterations)
        self.iterations_min = min(attack_iterations)
        self.iterations_max = max(attack_iterations)

        # Number of FGSM iterations for best result (successful attacks only)
        success_attack_iterations = []
        for s in samples:
            if s.results.best_result.attack_performed and s.results.best_result.evades_malconv:
                success_attack_iterations.append(s.results.best_result.iterations)
        self.success_iterations_avg = mean(success_attack_iterations)
        self.success_iterations_med = median(success_attack_iterations)
        self.success_iterations_std = 0.0
        if len(success_attack_iterations) > 1:
            self.success_iterations_std = stdev(success_attack_iterations)
        self.success_iterations_min = min(success_attack_iterations)
        self.success_iterations_max = max(success_attack_iterations)

        # Attack duration
        durations = []
        self.duration_tot = timedelta(0)
        for s in samples:
            durations.append(s.results.combined_duration.total_seconds())
            self.duration_tot = self.duration_tot + s.results.combined_duration
        self.duration_avg = timedelta(seconds=mean(durations))
        self.duration_med = timedelta(seconds=median(durations))
        self.duration_std = timedelta(0.0)
        if len(durations) > 1:
            self.duration_std = timedelta(seconds=stdev(durations))
        self.duration_min = timedelta(seconds=min(durations))
        self.duration_max = timedelta(seconds=max(durations))

        # Reconstruction phase duration
        rec_durations = []
        self.rec_duration_tot = timedelta(0)
        for s in samples:
            rec_durations.append(s.results.combined_reconstruction_duration.total_seconds())
            self.rec_duration_tot = self.rec_duration_tot + s.results.combined_reconstruction_duration
        self.rec_duration_avg = timedelta(seconds=mean(rec_durations))
        self.rec_duration_med = timedelta(seconds=median(rec_durations))
        self.rec_duration_std = timedelta(0.0)
        if len(rec_durations) > 1:
            self.rec_duration_std = timedelta(seconds=stdev(rec_durations))
        self.rec_duration_min = timedelta(seconds=min(rec_durations))
        self.rec_duration_max = timedelta(seconds=max(rec_durations))

        # MalConv classifications (initial)
        self.initial_scores_mal = 0
        malconv_scores_init = []
        for s in samples:
            malconv_scores_init.append(s.x_embermalconv_score * 100)
            if s.x_embermalconv_score >= 0.5:
                self.initial_scores_mal = self.initial_scores_mal + 1
        self.initial_scores_tot = len(malconv_scores_init)
        self.initial_scores_ben = self.initial_scores_tot - self.initial_scores_mal
        self.initial_scores_ben_pct = (self.initial_scores_ben / self.initial_scores_tot) * 100
        self.initial_scores_mal_pct = (self.initial_scores_mal / self.initial_scores_tot) * 100
        self.embermalconv_score_init_avg = mean(malconv_scores_init)
        self.embermalconv_score_init_med = median(malconv_scores_init)
        self.embermalconv_score_init_std = 0.0
        if len(malconv_scores_init) > 1:
            self.embermalconv_score_init_std = stdev(malconv_scores_init)
        self.embermalconv_score_init_min = min(malconv_scores_init)
        self.embermalconv_score_init_max = max(malconv_scores_init)

        # MalConv scores (perturbed embedded bytes)
        malconv_scores_emb = []
        for s in samples:
            malconv_scores_emb.append(s.results.best_result.z_new_embermalconv_score * 100)
        self.embermalconv_score_emb_avg = mean(malconv_scores_emb)
        self.embermalconv_score_emb_med = median(malconv_scores_emb)
        self.embermalconv_score_emb_std = 0
        if len(malconv_scores_emb) > 1:
            self.embermalconv_score_emb_std = stdev(malconv_scores_emb)
        self.embermalconv_score_emb_min = min(malconv_scores_emb)
        self.embermalconv_score_emb_max = max(malconv_scores_emb)

        # MalConv scores (perturbed embedded bytes - attacked samples with success only)
        success_malconv_scores_emb = []
        for s in samples:
            if s.results.best_result.attack_performed and s.results.best_result.evades_malconv:
                success_malconv_scores_emb.append(s.results.best_result.z_new_embermalconv_score * 100)
        self.success_embermalconv_score_emb_avg = mean(success_malconv_scores_emb)
        self.success_embermalconv_score_emb_med = median(success_malconv_scores_emb)
        self.success_embermalconv_score_emb_std = 0
        if len(success_malconv_scores_emb) > 1:
            self.success_embermalconv_score_emb_std = stdev(success_malconv_scores_emb)
        self.success_embermalconv_score_emb_min = min(success_malconv_scores_emb)
        self.success_embermalconv_score_emb_max = max(success_malconv_scores_emb)

        # MalConv scores (perturbed - all)
        self.final_scores_mal = 0
        malconv_scores_final = []
        for s in samples:
            malconv_scores_final.append(s.results.best_result.x_new_embermalconv_score * 100)
            if s.results.best_result.x_new_embermalconv_score >= 0.5:
                self.final_scores_mal = self.final_scores_mal + 1
        self.final_scores_tot = len(samples)
        self.final_scores_ben = self.final_scores_tot - self.final_scores_mal
        self.final_scores_ben_pct = (self.final_scores_ben / self.final_scores_tot) * 100
        self.final_scores_mal_pct = (self.final_scores_mal / self.final_scores_tot) * 100
        self.embermalconv_score_final_avg = mean(malconv_scores_final)
        self.embermalconv_score_final_med = median(malconv_scores_final)
        self.embermalconv_score_final_std = 0.0
        if len(malconv_scores_final) > 1:
            self.embermalconv_score_final_std = stdev(malconv_scores_final)
        self.embermalconv_score_final_min = min(malconv_scores_final)
        self.embermalconv_score_final_max = max(malconv_scores_final)

        # MalConv scores (perturbed - attacked samples with success only)
        success_malconv_scores_final = []
        for s in samples:
            if s.results.best_result.attack_performed and s.results.best_result.evades_malconv:
                success_malconv_scores_final.append(s.results.best_result.x_new_embermalconv_score * 100)
        self.success_embermalconv_score_final_avg = mean(success_malconv_scores_final)
        self.success_embermalconv_score_final_med = median(success_malconv_scores_final)
        self.success_embermalconv_score_final_std = 0.0
        if len(success_malconv_scores_final) > 1:
            self.success_embermalconv_score_final_std = stdev(success_malconv_scores_final)
        self.success_embermalconv_score_final_min = min(success_malconv_scores_final)
        self.success_embermalconv_score_final_max = max(success_malconv_scores_final)

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
        print(f'      Tot: {self.binsize_success_tot}')
        print(f'      Avg: {self.binsize_success_avg:.4f}')
        print(f'      Std: {self.binsize_success_std:.4f}')
        print(f'      Med: {self.binsize_success_med:.4f}')
        print(f'      Min: {self.binsize_success_min}')
        print(f'      Max: {self.binsize_success_max}')

        print(f'   Binary Size (failure cases):')
        print(f'      Tot: {self.binsize_failure_tot}')
        print(f'      Avg: {self.binsize_failure_avg:.4f}')
        print(f'      Std: {self.binsize_failure_std:.4f}')
        print(f'      Med: {self.binsize_failure_med:.4f}')
        print(f'      Min: {self.binsize_failure_min}')
        print(f'      Max: {self.binsize_failure_max}')

        print(f'   Payload Size (overlay - all samples):')
        print(f'      Avg: {self.payload_overlay_size_avg:.4f}')
        print(f'      Std: {self.payload_overlay_size_std:.4f}')
        print(f'      Med: {self.payload_overlay_size_med:.4f}')
        print(f'      Min: {self.payload_overlay_size_min}')
        print(f'      Max: {self.payload_overlay_size_max}')

        print(f'   Payload Size (overlay - successful attacks only):')
        print(f'      Avg: {self.success_payload_overlay_size_avg:.4f}')
        print(f'      Std: {self.success_payload_overlay_size_std:.4f}')
        print(f'      Med: {self.success_payload_overlay_size_med:.4f}')
        print(f'      Min: {self.success_payload_overlay_size_min}')
        print(f'      Max: {self.success_payload_overlay_size_max}')

        print(f'   Attack iterations (FGSM):')
        print(f'      Avg: {self.iterations_avg:.4f}')
        print(f'      Std: {self.iterations_std:.4f}')
        print(f'      Med: {self.iterations_med:.4f}')
        print(f'      Min: {self.iterations_min}')
        print(f'      Max: {self.iterations_max}')

        print(f'   Attack iterations (FGSM - successful attacks only):')
        print(f'      Avg: {self.success_iterations_avg:.4f}')
        print(f'      Std: {self.success_iterations_std:.4f}')
        print(f'      Med: {self.success_iterations_med:.4f}')
        print(f'      Min: {self.success_iterations_min}')
        print(f'      Max: {self.success_iterations_max}')

        print(f'   Attack duration:')
        print(f'      Tot: {format_timedelta(self.duration_tot)}')
        print(f'      Avg: {format_timedelta(self.duration_avg)}')
        print(f'      Std: {format_timedelta(self.duration_std)}')
        print(f'      Med: {format_timedelta(self.duration_med)}')
        print(f'      Min: {format_timedelta(self.duration_min)}')
        print(f'      Max: {format_timedelta(self.duration_max)}')

        print(f'   Reconstruction phase duration:')
        print(f'      Tot: {format_timedelta(self.rec_duration_tot)}')
        print(f'      Avg: {format_timedelta(self.rec_duration_avg)}')
        print(f'      Std: {format_timedelta(self.rec_duration_std)}')
        print(f'      Med: {format_timedelta(self.rec_duration_med)}')
        print(f'      Min: {format_timedelta(self.rec_duration_min)}')
        print(f'      Max: {format_timedelta(self.rec_duration_max)}')

        print(f'  EMBER MalConv Scores (Pre-Attack):')
        print(f'      Avg: {self.embermalconv_score_init_avg:.4f}')
        print(f'      Std: {self.embermalconv_score_init_std:.4f}')
        print(f'      Med: {self.embermalconv_score_init_med:.4f}')
        print(f'      Min: {self.embermalconv_score_init_min:.4f}')
        print(f'      Max: {self.embermalconv_score_init_max:.4f}')

        print(f'  EMBER MalConv Scores (Perturbed Embeddings, Pre-Reconstruction):')
        print(f'      Avg: {self.embermalconv_score_emb_avg:.4f}')
        print(f'      Std: {self.embermalconv_score_emb_std:.4f}')
        print(f'      Med: {self.embermalconv_score_emb_med:.4f}')
        print(f'      Min: {self.embermalconv_score_emb_min:.4f}')
        print(f'      Max: {self.embermalconv_score_emb_max:.4f}')

        print(f'  EMBER MalConv Scores (Perturbed Embeddings, Pre-Reconstruction - successful attacks only):')
        print(f'      Avg: {self.success_embermalconv_score_emb_avg:.4f}')
        print(f'      Std: {self.success_embermalconv_score_emb_std:.4f}')
        print(f'      Med: {self.success_embermalconv_score_emb_med:.4f}')
        print(f'      Min: {self.success_embermalconv_score_emb_min:.4f}')
        print(f'      Max: {self.success_embermalconv_score_emb_max:.4f}')

        print(f'  EMBER MalConv Scores (Post-Attack):')
        print(f'      Avg: {self.embermalconv_score_final_avg:.4f}')
        print(f'      Std: {self.embermalconv_score_final_std:.4f}')
        print(f'      Med: {self.embermalconv_score_final_med:.4f}')
        print(f'      Min: {self.embermalconv_score_final_min:.4f}')
        print(f'      Max: {self.embermalconv_score_final_max:.4f}')

        print(f'  EMBER MalConv Scores (Post-Attack - successful attacks only):')
        print(f'      Avg: {self.success_embermalconv_score_final_avg:.4f}')
        print(f'      Std: {self.success_embermalconv_score_final_std:.4f}')
        print(f'      Med: {self.success_embermalconv_score_final_med:.4f}')
        print(f'      Min: {self.success_embermalconv_score_final_min:.4f}')
        print(f'      Max: {self.success_embermalconv_score_final_max:.4f}')