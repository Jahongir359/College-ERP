from main_app import push

# Tests run without FCM credentials; skip the once-per-process "push is off" warning
# (test_push checks it on its own).
push._warned_off = True
