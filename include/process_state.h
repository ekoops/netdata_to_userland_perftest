#pragma once

#include <mutex>
#include <condition_variable>


class process_state {
    int state_ = 0;
    std::mutex m_;
    std::condition_variable cv_;
    std::chrono::time_point <std::chrono::system_clock> start_time_, end_time_;
public:
    int get_state() {
        std::unique_lock <std::mutex> ul {this->m_};
        return this->state_;
    }
    void wait() {
        std::unique_lock <std::mutex> ul{this->m_};
        while (this->state_ == 0) {
            this->cv_.wait(ul);
        }
    }
    void signal(void (*end_callback)() = nullptr) {
        std::unique_lock <std::mutex> ul{this->m_};
        if (this->state_ == 0) {
            this->start_time_ = std::chrono::system_clock::now();
        }
        this->state_++;
        if (this->state_ == 2) {
            this->end_time_ = std::chrono::system_clock::now();
            if (end_callback) {
                end_callback();
            }
        }
        this->cv_.notify_all();
    }
    std::chrono::duration<double> get_time() const {
        return this->end_time_ - this->start_time_;
    }
};