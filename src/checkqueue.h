// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <algorithm>
#include <vector>

#include <boost/foreach.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>

template <typename T>
class CCheckQueueControl;

/** 
 * Queue for verifications that have to be performed.
  * The verifications are represented by a type T, which must provide an
  * operator(), returning a bool.
  *
  * One thread (the master) is assumed to push batches of verifications
  * onto the queue, where they are processed by N-1 worker threads. When
  * the master is done adding work, it temporarily joins the worker pool
  * as an N'th worker, until all jobs are done.
  */
template <typename T>
class CCheckQueue
{
private:
    //! Mutex to protect the inner state
    boost::mutex mutex;

    //! Worker threads block on this when out of work
    boost::condition_variable condWorker;

    //! Master thread blocks on this when out of work
    boost::condition_variable condMaster;

    //! The queue of elements to be processed.
    //! As the order of booleans doesn't matter, it is used as a LIFO (stack)

    //! The number of workers (including the master) that are idle.
    int nIdle;

    //! The total number of workers (including the master).
    std::atomic<int> nTotal;

    //! The temporary evaluation result.
    std::atomic<uint8_t> fAllOk;

    /**
     * Number of verifications that haven't completed yet.
     * This includes elements that are no longer queued, but still in the
     * worker's own batches.
     */
    std::atomic<unsigned int> nTodo;

    //! Whether we're shutting down.
    bool fQuit;

    //! The maximum number of elements to be processed in one batch
    unsigned int nBatchSize;

    /** Internal function that does bulk of the verification work. */
    bool Loop(bool fMaster = false)
    {
        boost::condition_variable& cond = fMaster ? condMaster : condWorker;
        typename std::vector<T>::iterator checks_iterator;
        unsigned int nNow = 0;
        bool fOk = 1;
        // first iteration
        nTotal++;
        do {
            {
                boost::unique_lock<boost::mutex> lock(mutex);
                while (check_mem_top == check_mem_bottom) { // while (empty)
                    if (fMaster) {
                        // There's no harm to the master holding the lock
                        // at this point because all the jobs are taken.
                        // so busy spin
                        while (nTodo != 0) {}
                        nTotal--;
                        bool fRet = fAllOk;
                        // reset the status for new work later
                        fAllOk = 1;
                        // return the current status
                        return fRet;
                    } 
                    nIdle++;
                    cond.wait(lock); // wait
                    nIdle--;
                }
                // Decide how many work units to process now.
                // * Do not try to do everything at once, but aim for increasingly smaller batches so
                //   all workers finish approximately simultaneously.
                // * Try to account for idle jobs which will instantly start helping.
                // * Don't do batches smaller than 1 (duh), or larger than nBatchSize.
                nNow = std::max(1U, std::min(nBatchSize, (unsigned int)(check_mem_top - check_mem_bottom) / (nTotal + nIdle + 1)));
                checks_iterator = check_mem_bottom;
                std::advance(check_mem_bottom, nNow);
            }
            // Check whether we need to do work at all (can be read outside of
            // lock because it's fine if a worker executes checks anyways)
            fOk = fAllOk;
            // execute work
            for (unsigned int i = 0; i < nNow && fOk; i++) {
                fOk = (*checks_iterator)();
                auto t = T();
                checks_iterator->swap(t);
                std::advance(checks_iterator, 1);
            }
            fAllOk &= fOk;
            nTodo.fetch_sub(nNow);
        } while (true);
    }

public:
    //! Mutex to ensure only one concurrent CCheckQueueControl
    boost::mutex ControlMutex;

    //! Create a new check queue
    CCheckQueue(unsigned int nBatchSizeIn) : nIdle(0), nTotal(0), fAllOk(1), nTodo(0), fQuit(false), nBatchSize(nBatchSizeIn) {}

    //! Worker thread
    void Thread()
    {
        Loop();
    }

    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait()
    {
        return Loop(true);
    }

    typename std::vector<T>::iterator check_mem;
    typename std::vector<T>::iterator check_mem_top;
    typename std::vector<T>::iterator check_mem_bottom;
    void Setup(typename std::vector<T>::iterator check_mem_in) 
    {
        boost::unique_lock<boost::mutex> lock(mutex);
        check_mem = check_mem_in;
        check_mem_top = check_mem_in;
        check_mem_bottom = check_mem_in;
    }
    //! Add a batch of checks to the queue
    void Add(size_t size)
    {
        boost::unique_lock<boost::mutex> lock(mutex);
        check_mem_top += size;
        nTodo += size;
        if (size == 1)
            condWorker.notify_one();
        else if (size > 1)
            condWorker.notify_all();
    }

    ~CCheckQueue()
    {
    }

};

/** 
 * RAII-style controller object for a CCheckQueue that guarantees the passed
 * queue is finished before continuing.
 */
template <typename T>
class CCheckQueueControl
{
private:
    std::vector<T> check_mem;
    CCheckQueue<T>* pqueue;
    bool fDone;

public:
    CCheckQueueControl() = delete;
    CCheckQueueControl(const CCheckQueueControl&) = delete;
    CCheckQueueControl& operator=(const CCheckQueueControl&) = delete;
    explicit CCheckQueueControl(CCheckQueue<T> * const pqueueIn, const unsigned int size) : check_mem(), pqueue(pqueueIn), fDone(false)
    {
        // passed queue is supposed to be unused, or NULL
        if (pqueue != NULL) {
            ENTER_CRITICAL_SECTION(pqueue->ControlMutex);
            check_mem.reserve(size);
            pqueue->Setup(check_mem.begin());
        }
    }

    bool Wait()
    {
        if (pqueue == NULL)
            return true;
        bool fRet = pqueue->Wait();
        fDone = true;
        return fRet;
    }

    void Add(std::vector<T>& vChecks)
    {
        if (pqueue != NULL) {
            auto s = vChecks.size();
            for (T& x : vChecks) {
                check_mem.emplace_back();
                check_mem.back().swap(x);
            }
            pqueue->Add(s);
        }
    }
    template<typename ... Args>
    void Add(Args && ... args)
    {
        if (pqueue != NULL) {
            check_mem.emplace_back(std::forward<Args>(args)...);
        }
    }
    void Flush(size_t s)
    {
        if (pqueue != NULL) {
            pqueue->Add(s);
        }
    }

    ~CCheckQueueControl()
    {
        if (!fDone)
            Wait();
        if (pqueue != NULL) {
            LEAVE_CRITICAL_SECTION(pqueue->ControlMutex);
        }
    }
};

#endif // BITCOIN_CHECKQUEUE_H
