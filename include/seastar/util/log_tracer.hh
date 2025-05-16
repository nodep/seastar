#pragma once

#include <list>

namespace seastar {

struct dummy_type {};

using timestamp_t = std::chrono::time_point<std::chrono::system_clock>;

class buffer_full : public std::runtime_error {
public:
    buffer_full()
        : std::runtime_error("buffer is full") {
    }
};

struct log_trace {

    static constexpr int BUFF_SIZE = 1024*128;
    static constexpr int BUFFERS_IN_RING = 32;

    using buffer_t = std::array<char, BUFF_SIZE>;

    // Entry Format:
    // field            size in bytes
    //  timestamp       8
    //  format          8 (char*)
    //  arg count       1
    //  arguments:
    //    arg_type      1
    //    index         1
    //    size          2
    //    arg           size
    //  end             1 (null char)

    enum arg_type: uint8_t {
        e_other,
        e_int,
        e_uint,
        e_bool,
        e_string,
    };

    struct log_buffer {
        buffer_t buffer;

        buffer_t::iterator write_i = buffer.begin();
        buffer_t::iterator read_i = buffer.begin();

        uint8_t arg_count = 0;
        size_t entry_count = 0;

        log_buffer() {
            clear();
        }

        void clear() {
            write_i = buffer.begin();
            read_i = buffer.begin();
            arg_count = 0;
            entry_count = 0;
        }

        bool can_write(int bytes) const {
            return buffer.end() - write_i >= bytes;
        }

        bool can_read(int bytes) const {
            return buffer.end() - read_i >= bytes;
        }

        size_t buff_size() const {
            return write_i - buffer.begin();
        }

        size_t count() const {
            return entry_count;
        }

        template <typename T>
        void push(const T& t) {
            if (!can_write(sizeof(T))) {
                throw buffer_full();
            }

            const char* begin = (const char*) &t;
            const char* end = begin + sizeof(t);
            write_i = std::copy(begin, end, write_i);
        }
    
        template <typename T>
        void push_arg(const T& t, arg_type at) {
            push(at);
            push(arg_count);
            push(uint16_t(sizeof(T)));
            push(t);
        }
    
        template <typename T>
        T get() {
            T t;
            char* dest = (char*) &t;
            std::copy(read_i, read_i + sizeof(T), dest);
            read_i += sizeof(T);
            return t;
        }
    
        std::string getstr(size_t size) {
            std::string s;
            s.reserve(size);
            std::copy(read_i, read_i + size, std::back_inserter(s));
            read_i += size;
            return s;
        }
    
        void save_args() {
            // no args
        }
    
        void save_args(const std::string_view s);
        void save_args(const char* s);
        void save_args(const bool b);
    
        template <std::signed_integral I>
        void save_args(const I& i) {
            push_arg(i, e_int);
            ++arg_count;
        }
    
        template <std::unsigned_integral U>
        void save_args(const U& u) {
            push_arg(u, e_int);
            ++arg_count;
        }
    
        template <typename T>
        void save_args(const T& t) {
            // ignore arg -- we don't handle this (yet)
            ++arg_count;
        }
    
        template <typename T, typename... Args>
        void save_args(const T& t, Args&... args) {
            save_args(t);
            save_args(args...);
        }

        void commit_msg() {
            ++entry_count;
        }

        void flush();
    };

    struct ring_buffers {
        using ring_t = std::array<log_buffer, BUFFERS_IN_RING>;
        ring_t ring;
        ring_t::iterator write_buff_i = ring.begin();

        void rotate() {
            ++write_buff_i;
            if (write_buff_i == ring.end()) {
                write_buff_i = ring.begin();
            }

            write_buff_i->clear();
        }

        void flush() {
            ring_t::iterator flush_i = write_buff_i;
            do {
                ++flush_i;
                if (flush_i == ring.end()) {
                    flush_i = ring.begin();
                }

                flush_i->flush();
               
            } while (flush_i != write_buff_i);
        }

        log_buffer& active_buff() {
            return *write_buff_i;
        }
    };

    // TODO: get around the problem of dynamic creation and thread safety
    static constexpr int MAX_SHARDS = 32;
    std::array<std::unique_ptr<ring_buffers>, MAX_SHARDS> rbuffers;

    log_trace() = default;

    ring_buffers& get_buffers_for_this_shard() {
        const auto shard_id = this_shard_id();
        if (!rbuffers[shard_id]) {
            rbuffers[shard_id].reset(new ring_buffers{});
        }

        return *rbuffers[shard_id];
    }

    template <typename... Args>
    void write_log(const std::string_view& format, const Args&... args) {
        ring_buffers& rb = get_buffers_for_this_shard();
        while (true) {
            try {
                log_buffer& b = rb.active_buff();
                b.arg_count = 0;
                b.push(std::chrono::system_clock::now());
                b.push(format.data());    // we're betting on this being a null terminated string :)
                b.push(uint8_t(sizeof... (Args)));
                b.save_args(args...);
                b.push(uint8_t(e_other));

                b.commit_msg();

                break;
            } catch (buffer_full& e) {
                rb.rotate();
            }
        }
    }

    void flush() {
        for (auto& rb: rbuffers) {
            if (rb)
                rb->flush();
        }
    }
};

extern log_trace* log_trace_p;

}