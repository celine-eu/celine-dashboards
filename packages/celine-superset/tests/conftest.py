import pytest


class StartResponseRecorder:
    def __init__(self):
        self.status = None
        self.headers = None

    def __call__(self, status, headers):
        self.status = status
        self.headers = dict(headers)


@pytest.fixture()
def start_response():
    return StartResponseRecorder()
