import json
from pprint import pprint
import os
import sys
import time
import multiprocessing
from queue import Queue, Empty
from threading import Thread
import argparse
# from natsort import natsorted -> TODO make ordered 

sessions = {} # The name is sessions. JEFF sessions

# the provided thing should be a list of lists
def condenseHeaders(headers):
    result = '\r\n'

    for header in headers:
        result = result + header[0] + ': ' + header[1] + '\r\n'

    result += '\r\n'

    return result

def translate(in_dir, out_dir, isTesting, inQ, outQ, individual):
    global sessions
    count = 0
    
    while not inQ.empty():
        try:
            f = inQ.get()

            # can and will break if format changes
            session_name = "-".join(f.split("-")[0:-1])

            if session_name not in sessions:
                sessions[session_name] = {
                    "timestamp": int(time.time()),
                    "version": "0.1",
                    "txns": []
                }   

            if count == 5000 and isTesting:
                break

            name = f[:-4]

            if name == 'REPLACE ME?' and isTesting:
                continue

            # print("trying file {0}/{1}".format(in_dir, f))

            # no memory considerations whatsoever. feels 2017 man   
            fd = open('{0}/{1}'.format(in_dir, f), 'r', encoding='ascii', errors="surrogateescape")

            try:
                data = json.load(fd)
            except Exception as e:
                print("file {0}/{1} failed: {2}".format(in_dir, f, e))
                fd.close()
                continue
                
            fd.close()

            # pprint(data, stream=open('{0}/{1}_orig.json'.format(out_dir, name), 'w', encoding="ascii", errors="surrogateescape"), indent=4, width=sys.maxsize)

            # data['ua-request-line'] = data['ua-request-line'].replace('https', 'http')
            # data['ua-request-line'] = data['ua-request-line'].replace('HTTPS', 'HTTP')

            # filter out non-get requests
            if data['ua-request-line'].split(" ")[0] != 'GET':
                continue

            # skip, as per zeyuan
            if 'proxy-response-line' not in data:
                continue

            # filter out non-2xx responses
            try:
                if not data['proxy-response-line'].split(" ")[1].startswith('2'):
                    continue
            except Exception as e:
                print("file {0}/{1} failed filtering 2xx: {2}".format(in_dir, f, e))
                fd.close()
                continue


            # print("on file {0}/{1}".format(in_dir, f))

            # pprint(data, stream=open('{0}/{1}_http.json'.format(out_dir, name), 'w', encoding="ascii", errors="surrogateescape"), indent=4, width=sys.maxsize)

            try:
                txn = {"request": {}, "uuid": data["transaction-id"], "response": {}}
                
                txn["request"]["timestamp"] = data["start-time"]
                txn["request"]["headers"] = data["ua-request-line"] + condenseHeaders(data["ua-request-hdr"])
                txn["request"]["body"] = data["ua-content"] # this might not work because of the list thing?

                txn["response"]["timestamp"] = data["end-time"]
                txn["response"]["headers"] = data["proxy-response-line"] + condenseHeaders(data["proxy-response-hdr"])
                txn["response"]["body"] = data["upstream-content"] # this also might not work

                if individual:
                    result = {
                        "timestamp": int(time.time()),
                        "version": "0.1",
                        "txns": []
                    }

                    result["txns"].append(txn)
                    
                    outQ.put(("{0}/{1}.json".format(out_dir, name), result))
                else:
                    sessions[session_name]["txns"].append(txn)
            except Exception as e:
                print("file {0}/{1} failed: {2}".format(in_dir, f, e))
                continue

            count += 1

            # print(data["ua-request-line"])

            # print()
        except KeyboardInterrupt:
            break

def writeOut(out_dir, outQ, individual):
    global sessions
    print("Writing out results")

    if individual:
        while not outQ.empty():
            try:
                f = outQ.get(False)
            except Empty:
                break

            with open(f[0], "w", encoding="ascii", errors="surrogateescape") as out_f:
                json.dump(f[1], out_f, indent=4)
    else:
        for session in sessions:
                with open("{0}/{1}.json".format(out_dir, session), "w", encoding="ascii", errors="surrogateescape") as out_f:
                    json.dump(sessions[session], out_f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-j", type=int, dest='threads', default=4, help="number of threads to use")
    parser.add_argument("-i", type=str, dest='in_dir', help="input directory of log files")
    parser.add_argument("-o", type=str, dest='out_dir', help="output directory")
    parser.add_argument("--test", action="store_true", help="debug mode")
    parser.add_argument("--individual", action="store_true", help="instead of outputting sessions, output individual txns")

    args = parser.parse_args()
    print("got input folder {0} and output folder {1}".format(args.in_dir, args.out_dir))

    inQ = Queue()
    outQ = Queue()

    # put all the files into a Q
    for f in os.listdir(args.in_dir):
        inQ.put(f)

    Threads = []

    for i in range(max(args.threads - 1, 1)):
        t = Thread(target=translate, args=(args.in_dir, args.out_dir, args.test, inQ, outQ, args.individual))
        t.start()
        Threads.append(t)

    for t in Threads:
        t.join()

    writeOut(args.out_dir, outQ, args.individual)

    print("DONE")