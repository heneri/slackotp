import os
import multiprocessing

bind = '0.0.0.0:' + os.getenv('PORT', '8000')

max_requests = 1000
max_requests_jitter = 50

log_file = "-"
accesslog = "-"
access_log_format = '%(t)s %({x-forwarded-for}i)s %(l)s %(u)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

workers = (multiprocessing.cpu_count() * 2) + 1
threads = workers

timeout = 120