# frozen_string_literal: true

module Noise
  module Token
    E = 'e'
    S = 's'
    EE = 'ee'
    ES = 'es'
    SE = 'se'
    SS = 'ss'
    PSK = 'psk'
  end

  class Pattern
    attr_reader :one_way, :tokens

    def self.create(name)
      class_name = "Noise::Pattern#{name}"
      klass = Object.const_get(class_name)
      klass.new
    end

    def initialize
      @pre_messages = [[], []]
      @tokens = []
      @name = ''
      @one_way = false
      @psk_count = 0
    end

    # initiator [Boolean]
    def required_keypairs(initiator)
      initiator ? required_keypairs_of_initiator : required_keypairs_of_responder
    end

    def required_keypairs_of_initiator
      required = []
      required << :s if %w[K X I].include?(@name[0])
      required << :rs if @one_way || @name[1] == 'K'
      required
    end

    def required_keypairs_of_responder
      required = []
      required << :rs if @name[0] == 'K'
      required << :s if @one_way || %w[K X].include?(@name[1])
      required
    end

    def initiator_pre_messages
      @pre_messages[0].dup
    end

    def responder_pre_messages
      @pre_messages[1].dup
    end
  end

  class OneWayPattern < Pattern
    def initialize
      super
      @one_way = true
    end
  end

  class PatternN < OneWayPattern
    def initialize
      super
      @name = 'N'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES]]
    end
  end

  class PatternK < OneWayPattern
    def initialize
      super
      @name = 'K'
      @pre_messages = [[Token::S], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::SS]]
    end
  end

  class PatternX < OneWayPattern
    def initialize
      super
      @name = 'X'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::S, Token::SS]]
    end
  end

  class PatternNN < Pattern
    def initialize
      super
      @name = 'NN'
      @pre_messages = []
      @tokens = [[Token::E], [Token::E, Token::EE]]
    end
  end

  class PatternKN < Pattern
    def initialize
      super
      @name = 'KN'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternNK < Pattern
    def initialize
      super
      @name = 'NK'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES], [Token::E, Token::EE]]
    end
  end

  class PatternKK < Pattern
    def initialize
      super
      @name = 'KK'
      @pre_messages = [[Token::S], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::SS], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternNX < Pattern
    def initialize
      super
      @name = 'NX'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S, Token::ES]]
    end
  end

  class PatternKX < Pattern
    def initialize
      super
      @name = 'KX'
      @pre_messages = [[Token::S], []]
      @tokens = [[Token::E], [Token::E, Token::EE, Token::SE, Token::S, Token::ES]]
    end
  end

  class PatternXN < Pattern
    def initialize
      super
      @name = 'XN'
      @tokens = [[Token::E], [Token::E, Token::EE], [Token::S, Token::SE]]
    end
  end

  class PatternIN < Pattern
    def initialize
      super
      @name = 'IN'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternXK < Pattern
    def initialize
      super
      @name = 'XK'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES], [Token::E, Token::EE], [Token::S, Token::SE]]
    end
  end

  class PatternIK < Pattern
    def initialize
      super
      @name = 'IK'
      @pre_messages = [[], [Token::S]]
      @tokens = [[Token::E, Token::ES, Token::S, Token::SS], [Token::E, Token::EE, Token::SE]]
    end
  end

  class PatternXX < Pattern
    def initialize
      super
      @name = 'XX'
      @tokens = [[Token::E], [Token::E, Token::EE, Token::S, Token::ES], [Token::S, Token::SE]]
    end
  end

  class PatternIX < Pattern
    def initialize
      super
      @name = 'IX'
      @tokens = [[Token::E, Token::S], [Token::E, Token::EE, Token::SE, Token::S, Token::ES]]
    end
  end
end
