"""The shared checkout at .strange-security: a caller that commits a path of that name
must make the job fail (or, in gitleaks.yml, skip the report), and the Verify step must
prove the checkout really is a standalone repository at <workspace>/.strange-security.

actions/checkout follows a symlink at its target path and empties an existing directory
that has no .git before cloning into it, so a caller-committed '.strange-security -> sub'
would send the shared checkout into the caller's own sub/ and make the scans skip it.
The run blocks are extracted from the workflow files, so these tests cannot drift from
what CI executes."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from tests.test_sarif_report import workflow_steps, step_label
from tests.test_trivy_image_validation import BASH, extract_run_block
from tests.test_workflows import WORKFLOWS, read

PRECHECK = "Refuse caller-planted .strange-security path"
VERIFY = "Verify shared workflow checkout"
# (workflow, job) pairs that check out the shared source.
GATING = [("trivy.yml", "trivy"), ("semgrep.yml", "semgrep"), ("trivy-image.yml", "trivy-image"),
          ("trivy-images.yml", "plan"), ("trivy-images.yml", "scan")]
NON_GATING = [("gitleaks.yml", "gitleaks")]
# trivy-images' plan job has no caller checkout (it only runs the plan script), so there is
# nothing of the caller's in its workspace on a hosted runner; it still gets the pre-check.
NO_CALLER_CHECKOUT = {("trivy-images.yml", "plan")}


def jobs(text):
    """{job id: text of the job} for the jobs: section of a workflow."""
    start = re.search(r"(?m)^jobs:\s*$", text)
    body = text[start.end():] if start else ""
    parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", body)
    return dict(zip(parts[1::2], parts[2::2]))


def job_steps(text, job):
    return workflow_steps(jobs(text)[job])


def is_checkout(block):
    return bool(re.search(r"(?m)^\s*(?:- )?uses:\s*actions/checkout@", block))


def is_caller_checkout(block):
    return is_checkout(block) and not re.search(r"(?m)^\s*repository:", block)


def is_shared_checkout(block):
    return is_checkout(block) and bool(re.search(r"(?m)^\s*path:\s*\.strange-security\s*$", block))


def checkout_order_problems(text, workflow=""):
    """Problems with the order of caller checkout, pre-check and shared checkout in every
    job of a workflow that checks out the shared source."""
    problems = []
    for job, body in jobs(text).items():
        steps = workflow_steps(body)
        shared = [i for i, s in enumerate(steps) if is_shared_checkout(s)]
        if not shared:
            continue
        where = "%s:%s" % (workflow, job)
        if len(shared) != 1:
            problems.append(where + ": expected one shared checkout")
            continue
        pre = [i for i, s in enumerate(steps) if step_label(s) == PRECHECK]
        caller = [i for i, s in enumerate(steps) if is_caller_checkout(s)]
        if len(pre) != 1:
            problems.append(where + ": expected one pre-check step")
            continue
        if pre[0] > shared[0]:
            problems.append(where + ": pre-check comes after the shared checkout")
        if any(i > shared[0] for i in caller):
            problems.append(where + ": caller checkout comes after the shared checkout")
        if (workflow, job) not in NO_CALLER_CHECKOUT:
            if len(caller) != 1:
                problems.append(where + ": expected one caller checkout")
            elif caller[0] > pre[0]:
                problems.append(where + ": caller checkout comes after the pre-check")
    return problems


def workflow_files_with_shared_checkout():
    return [name for name in sorted(os.listdir(WORKFLOWS))
            if name.endswith(".yml")
            and any(is_shared_checkout(s) for body in jobs(read(name)).values() for s in workflow_steps(body))]


class Structure(unittest.TestCase):
    def test_every_job_that_checks_out_the_shared_source_is_covered(self):
        covered = sorted({name for name, _ in GATING + NON_GATING})
        self.assertEqual(workflow_files_with_shared_checkout(), covered)
        for name in covered:
            with_shared = [job for job, body in jobs(read(name)).items()
                           if any(is_shared_checkout(s) for s in workflow_steps(body))]
            self.assertEqual(sorted(with_shared), sorted(j for n, j in GATING + NON_GATING if n == name), name)

    def test_precheck_sits_between_the_caller_checkout_and_the_shared_checkout(self):
        for name in workflow_files_with_shared_checkout():
            self.assertEqual(checkout_order_problems(read(name), name), [], name)

    def test_a_missing_or_misplaced_precheck_is_detected(self):
        for name, job in GATING + NON_GATING:
            text = read(name).replace("\r\n", "\n")
            steps = job_steps(text, job)
            pre = next(s for s in steps if step_label(s) == PRECHECK)
            shared = next(s for s in steps if is_shared_checkout(s))
            self.assertEqual(checkout_order_problems(text, name), [], name)
            self.assertNotEqual(checkout_order_problems(text.replace(pre, ""), name), [], (name, "removed"))
            moved = text.replace(pre, "").replace(shared, shared + "\n" + pre)
            self.assertNotEqual(checkout_order_problems(moved, name), [], (name, "after the shared checkout"))

    def test_a_caller_checkout_after_the_shared_checkout_is_detected(self):
        for name, job in GATING + NON_GATING:
            if (name, job) in NO_CALLER_CHECKOUT:
                continue
            text = read(name).replace("\r\n", "\n")
            steps = job_steps(text, job)
            caller = next(s for s in steps if is_caller_checkout(s))
            shared = next(s for s in steps if is_shared_checkout(s))
            moved = text.replace(caller, "").replace(shared, shared + "\n" + caller)
            self.assertNotEqual(checkout_order_problems(moved, name), [], name)

    def test_gating_precheck_fails_the_job(self):
        for name, job in GATING:
            block = next(s for s in job_steps(read(name), job) if step_label(s) == PRECHECK)
            self.assertNotRegex(block, r"(?m)^\s*continue-on-error:", (name, job))
            self.assertNotRegex(block, r"(?m)^\s*if:", (name, job))
            self.assertIn("::error::The caller repository must not contain a .strange-security path", block)
            self.assertIn("[ -e .strange-security ] || [ -L .strange-security ]", block)
            self.assertNotIn("::warning::", block)

    def test_gitleaks_precheck_is_non_gating_and_gates_only_the_shared_checkout(self):
        text = read("gitleaks.yml")
        steps = job_steps(text, "gitleaks")
        pre = next(s for s in steps if step_label(s) == PRECHECK)
        self.assertRegex(pre, r"(?m)^        id: shared_precheck$")
        self.assertRegex(pre, r"(?m)^        continue-on-error: true$")
        self.assertNotRegex(pre, r"(?m)^\s*if:")
        self.assertIn("::warning::The caller repository must not contain a .strange-security path", pre)
        self.assertNotIn("::error::", pre)
        self.assertIn("[ -e .strange-security ] || [ -L .strange-security ]", pre)
        checkout = next(s for s in steps if is_shared_checkout(s))
        self.assertRegex(checkout, r"(?m)^        if: steps\.shared\.outcome == 'success' && "
                                   r"steps\.shared_precheck\.outcome == 'success'$")
        self.assertRegex(checkout, r"(?m)^        continue-on-error: true$")
        # Verify and the report keep their guards, which chain through the checkout outcome.
        verify = next(s for s in steps if step_label(s) == VERIFY)
        self.assertRegex(verify, r"(?m)^        if: steps\.shared_checkout\.outcome == 'success'$")
        # The install and scan steps neither depend on the pre-check nor can it fail them.
        for title in ("Install gitleaks", "Run gitleaks history scan"):
            block = next(s for s in steps if step_label(s) == title)
            self.assertNotIn("shared_precheck", block, title)
            self.assertNotRegex(block, r"(?m)^\s*if:", title)
            self.assertNotRegex(block, r"(?m)^\s*continue-on-error:", title)
        self.assertEqual(text.count("steps.shared_precheck"), 1)

    def test_verify_steps_check_symlink_location_and_toplevel(self):
        for name, job in GATING + NON_GATING:
            block = next(s for s in job_steps(read(name), job) if step_label(s) == VERIFY)
            self.assertIn("[ ! -L .strange-security ]", block, (name, job))
            self.assertIn("pwd -P", block, (name, job))
            self.assertIn('"$workspace/.strange-security"', block, (name, job))
            self.assertIn("git -C .strange-security rev-parse --show-toplevel", block, (name, job))
            self.assertIn("git -C .strange-security rev-parse HEAD", block, (name, job))
            self.assertIn("$WORKFLOW_SHA", block, (name, job))

    def test_scans_still_skip_the_shared_checkout(self):
        self.assertEqual(read("trivy.yml").count("--skip-dirs .strange-security"), 2)
        self.assertIn("--exclude .strange-security", read("semgrep.yml"))


def link_dir(target, link):
    """Make link a directory symlink to target; on Windows without symlink privilege a junction,
    which Git Bash also reports as a symlink. Raises OSError if neither can be made."""
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        if os.name != "nt":
            raise
        done = subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True)
        if done.returncode:
            raise OSError("cannot make a junction")


def unlink(path):
    try:
        os.unlink(path)
    except OSError:
        os.rmdir(path)


def can_link_dir(directory):
    """True if a directory symlink (or junction) can be made here and bash sees it as one."""
    probe = os.path.join(directory, "probe-link")
    try:
        link_dir(directory, probe)
    except OSError:
        return False
    try:
        return subprocess.run([BASH, "-c", '[ -L "$1" ]', "x", probe]).returncode == 0
    finally:
        unlink(probe)


def can_link_file(directory):
    """True if a file symlink can be made here and bash sees it as one."""
    target, probe = os.path.join(directory, "probe-target"), os.path.join(directory, "probe-link")
    with open(target, "w") as handle:
        handle.write("x\n")
    try:
        os.symlink(target, probe)
    except (OSError, NotImplementedError):
        return False
    try:
        return subprocess.run([BASH, "-c", '[ -L "$1" ]', "x", probe]).returncode == 0
    finally:
        unlink(probe)


def remove_tree(path):
    def writable(function, failed, _):
        os.chmod(failed, 0o700)
        function(failed)
    if os.path.islink(path) or (os.name == "nt" and os.path.isjunction(path)):
        unlink(path)
    elif os.path.exists(path):
        shutil.rmtree(path, onerror=writable)


def git(cwd, *args):
    done = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
                           *args], cwd=cwd, capture_output=True, text=True, check=True)
    return done.stdout.strip()


def make_repo(path, files=()):
    """A standalone repository at path holding the given relative files, one commit; its HEAD."""
    os.makedirs(path, exist_ok=True)
    git(path, "init", "-q")
    for relative in files:
        full = os.path.join(path, *relative.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("# x\n")
    git(path, "add", "-A")
    git(path, "commit", "-q", "--allow-empty", "-m", "x")
    return git(path, "rev-parse", "HEAD")


def required_files(script):
    """Files to create (relative to .strange-security) so every -f/-d test of the Verify block holds."""
    found = re.findall(r"-([df]) \.strange-security/(\S+)", script)
    assert found, "no required path found in the Verify block"
    return [path + "/.keep" if kind == "d" else path for kind, path in found]


@unittest.skipUnless(BASH and shutil.which("git"), "bash and git are required")
class RunBlocks(unittest.TestCase):
    """The real pre-check and Verify run blocks under bash -e, in temporary workspaces.
    Symlink cases are skipped on Windows without symlink privilege, never elsewhere."""

    KINDS = ["directory", "empty directory", "file", "symlink to a directory", "symlink to a file",
             "dangling symlink"]

    def block(self, name, job, title):
        return extract_run_block(os.path.join(WORKFLOWS, name), title, job)

    def run_block(self, script, cwd, **env):
        return subprocess.run([BASH, "-e", "-c", script], cwd=cwd, env=dict(os.environ, **env),
                              capture_output=True, text=True)

    def workspace(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        work = os.path.join(tmp.name, "work")
        os.makedirs(work)
        return tmp.name, work

    def need_dir_links(self, directory):
        if not can_link_dir(directory):
            if os.name == "nt":
                self.skipTest("neither symlinks nor junctions work here on Windows")
            self.fail("symlinks must work off Windows")

    def need_file_symlinks(self, directory):
        if not can_link_file(directory):
            if os.name == "nt":
                self.skipTest("file symlinks need privilege on Windows")
            self.fail("symlinks must work off Windows")

    def dangling_link(self, link, tmp):
        """A directory link whose target was removed again."""
        target = os.path.join(tmp, "gone")
        os.makedirs(target)
        link_dir(target, link)
        os.rmdir(target)

    def plant(self, kind, tmp, work):
        path = os.path.join(work, ".strange-security")
        if kind == "directory":
            os.makedirs(os.path.join(path, "sub"))
        elif kind == "empty directory":
            os.makedirs(path)
        elif kind == "file":
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("x\n")
        elif kind == "symlink to a directory":
            self.need_dir_links(tmp)
            os.makedirs(os.path.join(work, "sub"))
            link_dir(os.path.join(work, "sub"), path)
        elif kind == "symlink to a file":
            self.need_file_symlinks(tmp)
            with open(os.path.join(work, "target"), "w", encoding="utf-8") as handle:
                handle.write("x\n")
            os.symlink(os.path.join(work, "target"), path)
        elif kind == "dangling symlink":
            self.need_dir_links(tmp)
            self.dangling_link(path, tmp)
        else:
            raise AssertionError(kind)

    # -- the pre-check -------------------------------------------------------------------

    def test_precheck_passes_when_nothing_is_there(self):
        for name, job in GATING + NON_GATING:
            with self.subTest(workflow=name, job=job):
                _, work = self.workspace()
                os.makedirs(os.path.join(work, "src"))
                done = self.run_block(self.block(name, job, PRECHECK), work)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(done.stdout, "")

    def test_gating_precheck_fails_for_every_planted_path(self):
        for name, job in GATING:
            for kind in self.KINDS:
                with self.subTest(workflow=name, job=job, planted=kind):
                    tmp, work = self.workspace()
                    self.plant(kind, tmp, work)
                    done = self.run_block(self.block(name, job, PRECHECK), work)
                    self.assertNotEqual(done.returncode, 0, done.stdout)
                    self.assertIn("::error::The caller repository must not contain a .strange-security path",
                                  done.stdout)
                    self.assertNotIn("::warning::", done.stdout)

    def test_gitleaks_precheck_fails_only_itself_and_warns(self):
        script = self.block("gitleaks.yml", "gitleaks", PRECHECK)
        for kind in self.KINDS:
            with self.subTest(planted=kind):
                tmp, work = self.workspace()
                self.plant(kind, tmp, work)
                done = self.run_block(script, work)
                self.assertNotEqual(done.returncode, 0, done.stdout)
                self.assertIn("::warning::The caller repository must not contain a .strange-security path",
                              done.stdout)
                self.assertNotIn("::error", done.stdout)

    def test_the_precheck_only_looks_and_leaves_the_planted_path_alone(self):
        tmp, work = self.workspace()
        self.plant("directory", tmp, work)
        self.run_block(self.block("trivy.yml", "trivy", PRECHECK), work)
        self.assertTrue(os.path.isdir(os.path.join(work, ".strange-security", "sub")))

    # -- Verify --------------------------------------------------------------------------

    def expect_failure(self, name, done):
        self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)
        if name == "gitleaks.yml":
            self.assertIn("::warning::", done.stdout)
            self.assertNotIn("::error", done.stdout)
        else:
            self.assertIn("::error::", done.stdout)
            self.assertNotIn("::warning::", done.stdout)

    def proper(self, script, work):
        """A standalone shared checkout at work/.strange-security; its HEAD."""
        return make_repo(os.path.join(work, ".strange-security"), required_files(script))

    def test_verify_passes_for_a_standalone_repository_at_the_expected_path(self):
        for name, job in GATING + NON_GATING:
            with self.subTest(workflow=name, job=job):
                _, work = self.workspace()
                script = self.block(name, job, VERIFY)
                sha = self.proper(script, work)
                done = self.run_block(script, work, WORKFLOW_SHA=sha)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(done.stdout, "")

    def test_verify_passes_when_the_workspace_itself_is_reached_through_a_symlink(self):
        tmp, work = self.workspace()
        self.need_dir_links(tmp)
        link = os.path.join(tmp, "link")
        link_dir(work, link)
        for name, job in GATING + NON_GATING:
            with self.subTest(workflow=name, job=job):
                script = self.block(name, job, VERIFY)
                remove_tree(os.path.join(work, ".strange-security"))
                sha = self.proper(script, work)
                done = self.run_block(script, link, WORKFLOW_SHA=sha)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_verify_fails_for_a_symlinked_checkout_even_when_it_is_genuine(self):
        for name, job in GATING + NON_GATING:
            with self.subTest(workflow=name, job=job):
                tmp, work = self.workspace()
                self.need_dir_links(tmp)
                script = self.block(name, job, VERIFY)
                # A genuine repository at the right commit with every file, but reached through
                # a symlink, as when actions/checkout followed a symlink the caller committed.
                sha = make_repo(os.path.join(tmp, "elsewhere"), required_files(script))
                link_dir(os.path.join(tmp, "elsewhere"), os.path.join(work, ".strange-security"))
                self.expect_failure(name, self.run_block(script, work, WORKFLOW_SHA=sha))

    def test_verify_fails_for_a_symlink_to_a_directory_of_the_caller(self):
        for name, job in GATING + NON_GATING:
            with self.subTest(workflow=name, job=job):
                tmp, work = self.workspace()
                self.need_dir_links(tmp)
                script = self.block(name, job, VERIFY)
                sha = make_repo(os.path.join(work, "sub"), required_files(script))
                link_dir(os.path.join(work, "sub"), os.path.join(work, ".strange-security"))
                self.expect_failure(name, self.run_block(script, work, WORKFLOW_SHA=sha))

    def test_verify_fails_for_a_subdirectory_of_another_repository(self):
        for name, job in GATING + NON_GATING:
            with self.subTest(workflow=name, job=job):
                _, work = self.workspace()
                script = self.block(name, job, VERIFY)
                # The caller's repository holds .strange-security as a plain subdirectory. Its HEAD
                # is the expected commit and every file test passes: only the git top level, which
                # is the caller's root, gives it away.
                sha = make_repo(work, [".strange-security/" + p for p in required_files(script)])
                self.expect_failure(name, self.run_block(script, work, WORKFLOW_SHA=sha))

    def test_verify_fails_for_a_directory_that_is_not_a_repository(self):
        for name, job in GATING + NON_GATING:
            with self.subTest(workflow=name, job=job):
                _, work = self.workspace()
                script = self.block(name, job, VERIFY)
                for path in required_files(script):
                    full = os.path.join(work, ".strange-security", *path.split("/"))
                    os.makedirs(os.path.dirname(full), exist_ok=True)
                    open(full, "w").close()
                self.expect_failure(name, self.run_block(script, work, WORKFLOW_SHA="a" * 40))

    def test_verify_fails_for_a_file_or_nothing_at_the_path(self):
        for name, job in GATING + NON_GATING:
            with self.subTest(workflow=name, job=job):
                _, work = self.workspace()
                script = self.block(name, job, VERIFY)
                self.expect_failure(name, self.run_block(script, work, WORKFLOW_SHA="a" * 40))
                with open(os.path.join(work, ".strange-security"), "w") as handle:
                    handle.write("x\n")
                self.expect_failure(name, self.run_block(script, work, WORKFLOW_SHA="a" * 40))

    def test_verify_keeps_the_commit_and_file_checks(self):
        for name, job in GATING + NON_GATING:
            with self.subTest(workflow=name, job=job):
                _, work = self.workspace()
                script = self.block(name, job, VERIFY)
                sha = self.proper(script, work)
                for wrong in ("b" * 40, "", sha[:12]):
                    self.expect_failure(name, self.run_block(script, work, WORKFLOW_SHA=wrong))
                files = required_files(script)
                for omitted in range(len(files)):
                    remove_tree(os.path.join(work, ".strange-security"))
                    sha = make_repo(os.path.join(work, ".strange-security"),
                                    [f for i, f in enumerate(files) if i != omitted])
                    done = self.run_block(script, work, WORKFLOW_SHA=sha)
                    self.assertNotEqual(done.returncode, 0, (files[omitted], done.stdout))


if __name__ == "__main__":
    unittest.main()
