#ifndef __FU_THREAD_POOL_H__
#define __FU_THREAD_POOL_H__

#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <vector>
// using namespace std;
// namespace utils {
class ThreadPool {
 public:
  ThreadPool(size_t);
  //   template <class F, class... Args>
  //   auto enqueue(F&& f, Args&&... args)
  //       -> std::future<typename std::result_of<F(Args...)>::type>;

  template <class F, class... Args>
  std::future<typename std::result_of<F(Args...)>::type> enqueue(
      F&& f, Args&&... args);
  ~ThreadPool();
  bool isAllThreadBusy(int& useCount) {
    useCount = _busy_count.load();
    if (useCount < _thread_num) {
      return false;
    }
    return true;
  };

 private:
  // need to keep track of threads so we can join them
  std::vector<std::thread> workers;
  // the task queue
  //   std::queue<std::function<void()>> tasks;
  std::deque<std::function<void()>> tasks;

  // synchronization
  std::mutex queue_mutex;
  std::condition_variable condition;
  bool stop;
  std::atomic<int> _busy_count;
  int _thread_num;
};

// the constructor just launches some amount of workers
inline ThreadPool::ThreadPool(size_t threads) : stop(false) {
  _busy_count.store(0);
  _thread_num = threads;
  for (size_t i = 0; i < threads; ++i)
    workers.emplace_back([this] {
      for (;;) {
        std::function<void()> task;

        {
          std::unique_lock<std::mutex> lock(this->queue_mutex);
          this->condition.wait(
              lock, [this] { return this->stop || !this->tasks.empty(); });
          if (this->stop && this->tasks.empty()) return;
          task = std::move(this->tasks.front());
          this->tasks.pop_front();
        }
        _busy_count.fetch_add(1);
        task();
        _busy_count.fetch_sub(1);
      }
    });
}

// add new work item to the pool
template <class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args)
    -> std::future<typename std::result_of<F(Args...)>::type> {
  using return_type = typename std::result_of<F(Args...)>::type;
  //   cout << "return_type:" << decltype(return_type);
  auto task = std::make_shared<std::packaged_task<return_type()>>(
      std::bind(std::forward<F>(f), std::forward<Args>(args)...));
  //   cout << return_type() << endl;
  std::future<return_type> res = task->get_future();
  {
    std::unique_lock<std::mutex> lock(queue_mutex);

    // don't allow enqueueing after stopping the pool
    if (stop) throw std::runtime_error("enqueue on stopped ThreadPool");

    // tasks.emplace([task]() { (*task)(); });
    tasks.emplace_back([task]() { (*task)(); });
    // tasks.push()
  }
  condition.notify_one();
  return res;
}

// the destructor joins all threads
inline ThreadPool::~ThreadPool() {
  {
    std::unique_lock<std::mutex> lock(queue_mutex);
    stop = true;
  }
  condition.notify_all();
  for (std::thread& worker : workers) worker.join();
  std::cout << "~ThreadPool ...." << std::endl;
}
// }  // namespace utils
#endif
