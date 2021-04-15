/* Copyright (c) 2016-2017, ARM Limited and Contributors
  *
  * SPDX-License-Identifier: MIT
  *
  * Permission is hereby granted, free of charge,
  * to any person obtaining a copy of this software and associated documentation files (the "Software"),
  * to deal in the Software without restriction, including without limitation the rights to
  * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
  * and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
  * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
  * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  */

#include "threadPool.h"
#include <utility>

namespace koal
{
	void ThreadPool::setWorkerThreadCount(unsigned workerThreadCount)
	{
		if (0 == workerThreadCount)
			workerThreadCount = std::thread::hardware_concurrency();

		workerThreads.clear();
		for (unsigned i = 0; i < workerThreadCount; i++)
			workerThreads.emplace_back(new Worker);
	}

	void ThreadPool::pushWorkToThread(ITask *task)
	{
		static short threadIndex = 0;
		workerThreads[threadIndex]->pushWork(std::move(task));
		threadIndex = threadIndex >= workerThreads.size() - 1 ? 0 : ++threadIndex;
	}

	void ThreadPool::waitIdle()
	{
		for (auto &worker : workerThreads)
			worker->waitIdle();
	}

	ThreadPool::Worker::Worker()
	{
		workerThread = std::thread(&ThreadPool::Worker::threadEntry, this);
	}

	ThreadPool::Worker::~Worker()
	{
		if (workerThread.joinable())
		{
			waitIdle();

			lock.lock();
			threadIsAlive = false;
			cond.notify_one();
			lock.unlock();

			workerThread.join();
		}
	}

	void ThreadPool::Worker::pushWork(ITask *task)
	{
		std::lock_guard<std::mutex> holder{ lock };
		workQueue.push(std::move(task));
		cond.notify_one();
	}

	void ThreadPool::Worker::waitIdle()
	{
		std::unique_lock<std::mutex> holder{ lock };
		cond.wait(holder, [this] { return workQueue.empty(); });
	}

	void ThreadPool::Worker::threadEntry()
	{
		for (;;)
		{
			ITask *task = nullptr;
			{
				std::unique_lock<std::mutex> holder{ lock };
				cond.wait(holder, [this] { return !workQueue.empty() || !threadIsAlive; });
				if (!threadIsAlive)
					break;

				task = workQueue.front();
			}

			task->Run();

			{
				std::lock_guard<std::mutex> holder{ lock };
				workQueue.pop();
				delete task;
				cond.notify_one();
			}
		}
	}
}


