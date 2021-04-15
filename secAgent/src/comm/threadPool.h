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

#ifndef FRAMEWORK_THREAD_POOL_HPP
#define FRAMEWORK_THREAD_POOL_HPP

#include "task.hpp"
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>

namespace koal
{
	class ThreadPool
	{
	public:
		void setWorkerThreadCount(unsigned workerThreadCount = 0);

		unsigned getWorkerThreadCount() const
		{
			return workerThreads.size();
		}

		void pushWorkToThread(ITask *task);

		void waitIdle();

	public:
		class Worker
		{
		public:
			Worker();
			~Worker();

			void pushWork(ITask *task);
			void waitIdle();

		private:
			std::thread workerThread;
			std::mutex lock;
			std::condition_variable cond;

			std::queue<ITask *> workQueue;
			bool threadIsAlive = true;

			void threadEntry();
		};

		std::vector<std::unique_ptr<Worker>> workerThreads;
	};
}

#endif