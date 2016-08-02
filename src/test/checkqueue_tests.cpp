// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "utiltime.h"

#include "test/test_bitcoin.h"
#include "checkqueue.h"

#include <boost/test/unit_test.hpp>
#include <atomic>

#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <unordered_set>
boost::thread_group threadGroup;
BOOST_FIXTURE_TEST_SUITE(checkqueue_tests, BasicTestingSetup)


static std::atomic<size_t> n;
struct FakeJobCheckCompletion {
    bool operator()(std::function<void()>& z)
    {
        ++n;
        return true;
    }
    bool operator()()
    {
        ++n;
        return true;
    }

    void swap(FakeJobCheckCompletion& x){};
};
struct FakeJobNoWork {
    bool operator()()
    {
        return true;
    }
    bool operator()(std::function<void()>& z)
    {
        return true;
    }
    void swap(FakeJobNoWork& x){};
};

struct FailingJob {
    bool f;
    FailingJob(bool fails) : f(fails){};
    FailingJob() : f(true){};
    bool operator()()
    {
        return !f;
    }
    bool operator()(std::function<void()>& z)
    {
        return !f;
    }
    void swap(FailingJob& x) { std::swap(f, x.f); };
};
typedef CCheckQueue<FakeJobCheckCompletion, (size_t)100000, 16> big_queue;

BOOST_AUTO_TEST_CASE(test_CheckQueue_PriorityWorkQueue)
{
    fPrintToConsole = true;
    CCheckQueue_Internals::PriorityWorkQueue<big_queue::Proto> work(0, 16);
    auto m = 0;
    work.add(100);
    BOOST_CHECK(!work.empty());
    size_t x = work.pop();
    BOOST_CHECK(x == 0);
    size_t x2 = work.pop();
    BOOST_TEST_MESSAGE("GOT: x2 = " << x2);
    BOOST_CHECK(x2 == 16);
    m = 2;
    while (!work.empty()) {
        work.pop();
        ++m;
    }
    BOOST_CHECK(m == 100);
    work.add(200);
    std::unordered_set<size_t> results;
    while (!work.empty()) {
        results.insert(work.pop());
        ++m;
    }
    for (auto i = 100; i < 200; ++i)
        results.erase(i);
    BOOST_CHECK(results.empty());
    BOOST_CHECK(m == 200);

    work.reset();

    work.add(1000);

    m = 0;
    try {
        for (;;) {
            work.pop();
            ++m;
        }
    } catch (...) {
    }
    BOOST_CHECK(m == 1000);
}

CCheckQueue_Internals::job_array<big_queue::Proto> jobs;
static std::atomic<size_t> m;
BOOST_AUTO_TEST_CASE(test_CheckQueue_job_array)
{
    fPrintToConsole = true;
    for (size_t i = 0; i < big_queue::MAX_JOBS; ++i)
        jobs.reset_flag(i);
    m = 0;
    threadGroup.create_thread([]() {
            for (size_t i = 0; i < big_queue::MAX_JOBS; ++i)
            m += jobs.reserve(i) ? 1 : 0;
    });

    threadGroup.create_thread([]() {
            for (size_t i = 0; i < big_queue::MAX_JOBS; ++i)
            m += jobs.reserve(i) ? 1 : 0;
    });
    threadGroup.join_all();

    BOOST_CHECK(m == big_queue::MAX_JOBS);
}
BOOST_AUTO_TEST_CASE(test_CheckQueue_round_barrier)
{
    static CCheckQueue_Internals::round_barrier<big_queue::Proto> barrier;
    fPrintToConsole = true;
    barrier.reset(8);
    for (int i = 0; i < 8; ++i)
        threadGroup.create_thread([=]() {
            decltype(barrier)::Cache cache;
            barrier.mark_done(i, cache);
            while (!barrier.load_done(8, cache))
                boost::this_thread::yield();
        });

    threadGroup.create_thread([]() {
    });
    threadGroup.join_all();
}


BOOST_AUTO_TEST_CASE(test_CheckQueue_quit)
{
    static CCheckQueue<FakeJobCheckCompletion, (size_t)100, 16> small_queue;

    fPrintToConsole = true;
    auto nThreads = 8;
    for (auto i = 0; i < nThreads - 1; ++i)
        threadGroup.create_thread([=]() {small_queue.Thread(nThreads); });
    small_queue.quit_queue();
    threadGroup.join_all();
}

BOOST_AUTO_TEST_CASE(test_CheckQueue_Performance)
{
    static CCheckQueue<FakeJobNoWork, (size_t)100000, 16> fast_queue;
    fPrintToConsole = true;
    auto nThreads = 8;
    for (auto i = 0; i < nThreads - 1; ++i)
        threadGroup.create_thread([=]() {fast_queue.Thread(nThreads); });

    std::vector<FakeJobNoWork> vChecks;
    vChecks.reserve(100);
    auto start_time = GetTimeMicros();
    size_t ROUNDS = 1000;
    for (size_t i = 0; i < ROUNDS; ++i) {
        size_t total = 0;
        {
            n = 0;
            CCheckQueueControl<decltype(fast_queue)> control(&fast_queue, nThreads);
            for (size_t j = 0; j < 101; ++j) {
                size_t r = 30;
                total += r;
                vChecks.clear();
                for (size_t k = 0; k < r; ++k)
                    vChecks.push_back(FakeJobNoWork{});
                control.Add(vChecks);
            }
        }
    }
    auto end_time = GetTimeMicros();
    BOOST_TEST_MESSAGE("Perf Test took " << end_time - start_time << " microseconds for 100 rounds, " << (ROUNDS * 1000000.0) / (end_time - start_time) << "rps");
    fast_queue.quit_queue();
    threadGroup.join_all();
}

BOOST_AUTO_TEST_CASE(test_CheckQueue_Catches_Failure)
{
    static CCheckQueue<FailingJob, (size_t)100, 16> fail_queue;
    fPrintToConsole = true;
    auto nThreads = 8;
    for (auto i = 0; i < nThreads - 1; ++i)
        threadGroup.create_thread([=]() {fail_queue.Thread(nThreads); });

    size_t count = 0;
    for (size_t i = 0; i < 101; ++i) {
        size_t total = i;
        n = 0;
        CCheckQueueControl<decltype(fail_queue)> control(&fail_queue, nThreads);
        while (total) {
            size_t r = GetRand(10);
            std::vector<FailingJob> vChecks;
            vChecks.reserve(r);
            for (size_t k = 0; k < r && total; k++) {
                total--;
                vChecks.push_back(FailingJob{total == 0});
            }
            control.Add(vChecks);
        }
        BOOST_CHECK(control.Wait() == (i == 0));
        ++count;
    }
    fail_queue.quit_queue();
    threadGroup.join_all();
}
BOOST_AUTO_TEST_CASE(test_CheckQueue_Correct)
{
    static CCheckQueue<FakeJobCheckCompletion, (size_t)100, 16> small_queue;
    fPrintToConsole = true;
    auto nThreads = 8;
    for (auto i = 0; i < nThreads - 1; ++i)
        threadGroup.create_thread([=]() {small_queue.Thread(nThreads); });

    size_t count = 0;
    for (size_t i = 0; i < 101; ++i) {
        size_t total = i;
        {
            n = 0;
            CCheckQueueControl<decltype(small_queue)> control(&small_queue, nThreads);
            while (total) {
                size_t r = GetRand(10);
                std::vector<FakeJobCheckCompletion> vChecks;
                vChecks.reserve(r);
                for (size_t k = 0; k < r && total; k++) {
                    total--;
                    vChecks.push_back(FakeJobCheckCompletion{});
                }
                control.Add(vChecks);
            }
        }
        ++count;
        if (n != i) {
            BOOST_TEST_MESSAGE("Failure on trial " << count - 1);
        }
    }
    small_queue.quit_queue();
    threadGroup.join_all();
}

BOOST_AUTO_TEST_SUITE_END()
