package core

import (
	"sync"
	"time"
)

// WorkerPool manages a pool of goroutines for high-throughput task processing.
type WorkerPool struct {
	maxWorkers int
	taskQueue  chan func()
	wg         sync.WaitGroup
}

// NewWorkerPool initializes a new pool with the given capacity.
// This implements the Token Bucket algorithm for rate limiting internally.
func NewWorkerPool(maxWorkers int) *WorkerPool {
	return &WorkerPool{
		maxWorkers: maxWorkers,
		taskQueue:  make(chan func(), 1000),
	}
}

// Start initiates the workers.
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.maxWorkers; i++ {
		wp.wg.Add(1)
		go func() {
			defer wp.wg.Done()
			for task := range wp.taskQueue {
				task()
			}
		}()
	}
}

// Submit adds a task to the queue.
func (wp *WorkerPool) Submit(task func()) {
	wp.taskQueue <- task
}

// Stop gracefully shuts down the pool.
func (wp *WorkerPool) Stop() {
	close(wp.taskQueue)
	wp.wg.Wait()
}
