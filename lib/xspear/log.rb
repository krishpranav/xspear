def log(t, message)
    if @verbose.to_i == 1
      if t == 's' # system message
        puts '[*]'.green + " #{message}"
      end
    elsif @verbose.to_i > 1
      time = Time.now
      if t == 'd'
        puts '[-]'.white + " [#{time.strftime('%H:%M:%S')}] #{message}"
      elsif t == 's' # system message
        puts '[*]'.green + " #{message}"
      elsif t == 'i'
        puts '[I]'.blue + " [#{time.strftime('%H:%M:%S')}] #{message}"
      elsif t == 'v'
        puts '[V]'.red + " [#{time.strftime('%H:%M:%S')}] #{message}"
      elsif t == 'l'
        puts '[L]'.blue + " [#{time.strftime('%H:%M:%S')}] #{message}"
      elsif t == 'm'
        puts '[M]'.yellow + " [#{time.strftime('%H:%M:%S')}] #{message}"
      elsif t == 'h'
        puts '[H]'.red + " [#{time.strftime('%H:%M:%S')}] #{message}"
      end
    end
  end